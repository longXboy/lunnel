package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/longXboy/Lunnel/contrib"
	"github.com/longXboy/Lunnel/crypto"
	"github.com/longXboy/Lunnel/msg"
	"github.com/longXboy/Lunnel/util"
	"github.com/longXboy/smux"
	"github.com/pkg/errors"
)

var maxIdlePipes int = 3
var maxStreams int = 6

var pingInterval time.Duration = time.Second * 30
var pingTimeout time.Duration = time.Second * 70
var cleanInterval time.Duration = time.Second * 5

var ControlMapLock sync.RWMutex
var ControlMap = make(map[crypto.UUID]*Control)

var subDomainIdx uint64

var TunnelMapLock sync.RWMutex
var TunnelMap = make(map[string]*Tunnel)

func NewControl(conn net.Conn, encryptMode string) *Control {
	ctl := &Control{
		ctlConn:     conn,
		pipeGet:     make(chan *smux.Session),
		pipeAdd:     make(chan *smux.Session),
		die:         make(chan struct{}),
		toDie:       make(chan struct{}),
		writeChan:   make(chan writeReq, 128),
		encryptMode: encryptMode,
		tunnels:     make(map[string]*Tunnel, 0),
	}
	return ctl
}

type writeReq struct {
	mType msg.MsgType
	body  interface{}
}

type Tunnel struct {
	tunnelConfig msg.TunnelConfig
	listener     net.Listener
	tunnelName   string
	ctl          *Control
}

func (t Tunnel) Close() {
	if t.listener != nil {
		t.listener.Close()
	}
	TunnelMapLock.Lock()
	delete(TunnelMap, t.tunnelConfig.RemoteAddr())
	TunnelMapLock.Unlock()
	if serverConf.NotifyEnable {
		err := contrib.RemoveMember(serverConf.ServerDomain, t.tunnelConfig.RemoteAddr())
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("notify remove member failed!")
		}
	}
}

type pipeNode struct {
	prev *pipeNode
	next *pipeNode
	pipe *smux.Session
}

type Control struct {
	ctlConn         net.Conn
	tunnels         map[string]*Tunnel
	tunnelLock      sync.Mutex
	preMasterSecret []byte
	lastRead        uint64
	encryptMode     string

	busyPipes  *pipeNode
	idleCount  int
	idlePipes  *pipeNode
	totalPipes int64
	pipeAdd    chan *smux.Session
	pipeGet    chan *smux.Session

	die       chan struct{}
	toDie     chan struct{}
	writeChan chan writeReq

	ClientID crypto.UUID
}

func (c *Control) addIdlePipe(pipe *smux.Session) {
	pNode := &pipeNode{pipe: pipe, prev: nil, next: nil}
	if c.idlePipes != nil {
		c.idlePipes.prev = pNode
		pNode.next = c.idlePipes
	}
	c.idlePipes = pNode
	c.idleCount++

}

func (c *Control) addBusyPipe(pipe *smux.Session) {
	pNode := &pipeNode{pipe: pipe, prev: nil, next: nil}
	if c.busyPipes != nil {
		c.busyPipes.prev = pNode
		pNode.next = c.busyPipes
	}
	c.busyPipes = pNode
}

func (c *Control) removeIdleNode(pNode *pipeNode) {
	if pNode.prev == nil {
		c.idlePipes = pNode.next
		if c.idlePipes != nil {
			c.idlePipes.prev = nil
		}
	} else {
		pNode.prev.next = pNode.next
		if pNode.next != nil {
			pNode.next.prev = pNode.prev
		}
	}
	c.idleCount--
}

func (c *Control) removeBusyNode(pNode *pipeNode) {
	if pNode.prev == nil {
		c.busyPipes = pNode.next
		if c.busyPipes != nil {
			c.busyPipes.prev = nil
		}
	} else {
		pNode.prev.next = pNode.next
		if pNode.next != nil {
			pNode.next.prev = pNode.prev
		}
	}
}

func (c *Control) putPipe(p *smux.Session) {
	select {
	case c.pipeAdd <- p:
	case <-c.die:
		atomic.AddInt64(&c.totalPipes, -1)
		p.Close()
		return
	}
	return
}

func (c *Control) getPipe() *smux.Session {
	select {
	case p := <-c.pipeGet:
		return p
	case <-c.die:
		return nil
	}
}

func (c *Control) clean() {
	if atomic.LoadInt64(&c.totalPipes) > int64(maxIdlePipes) {
		log.WithFields(log.Fields{"total_pipe_count": atomic.LoadInt64(&c.totalPipes), "client_id": c.ClientID.Hex()}).Debugln("total pipe count")
	}
	busy := c.busyPipes
	for {
		if busy == nil {
			break
		}
		if busy.pipe.IsClosed() {
			c.removeBusyNode(busy)
		} else if busy.pipe.NumStreams() < maxStreams {
			c.removeBusyNode(busy)
			c.addIdlePipe(busy.pipe)
		}
		busy = busy.next
	}
	idle := c.idlePipes
	for {
		if idle == nil {
			return
		}
		if idle.pipe.IsClosed() {
			c.removeIdleNode(idle)
		} else if idle.pipe.NumStreams() == 0 && c.idleCount >= maxIdlePipes {
			log.WithFields(log.Fields{"time": time.Now().Unix(), "pipe": fmt.Sprintf("%p", idle.pipe), "client_id": c.ClientID.Hex()}).Infoln("remove and close idle")
			c.removeIdleNode(idle)
			atomic.AddInt64(&c.totalPipes, -1)
			idle.pipe.Close()
		}
		idle = idle.next
	}
	return

}
func (c *Control) getIdleFast() (idle *pipeNode) {
	idle = c.idlePipes
	for {
		if idle == nil {
			return
		}
		if idle.pipe.IsClosed() {
			c.removeIdleNode(idle)
			idle = idle.next
		} else {
			c.removeIdleNode(idle)
			return
		}
	}
	return
}

func (c *Control) pipeManage() {
	var available *smux.Session
	ticker := time.NewTicker(cleanInterval)
	defer ticker.Stop()
	for {
	Prepare:
		if available == nil || available.IsClosed() {
			available = nil
			idle := c.getIdleFast()
			if idle == nil {
				c.clean()
				idle := c.getIdleFast()
				c.writeChan <- writeReq{msg.TypePipeReq, nil}
				if idle == nil {
					pipeGetTimeout := time.After(time.Second * 12)
					for {
						select {
						case <-ticker.C:
							c.clean()
							idle := c.getIdleFast()
							if idle != nil {
								available = idle.pipe
								goto Available
							}
						case p := <-c.pipeAdd:
							if !p.IsClosed() {
								if p.NumStreams() < maxStreams {
									available = p
									goto Available
								} else {
									c.addBusyPipe(p)
								}
							}
						case <-c.die:
							return
						case <-pipeGetTimeout:
							goto Prepare
						}
					}
				} else {
					available = idle.pipe
				}
			} else {
				available = idle.pipe
			}
		}
	Available:
		select {
		case <-ticker.C:
			c.clean()
		case c.pipeGet <- available:
			log.WithFields(log.Fields{"pipe": fmt.Sprintf("%p", available), "client_id": c.ClientID.Hex()}).Infoln("dispatch pipe to consumer")
			available = nil
		case p := <-c.pipeAdd:
			if !p.IsClosed() {
				if p.NumStreams() < maxStreams {
					c.addIdlePipe(p)
				} else {
					c.addBusyPipe(p)
				}
			}
		case <-c.die:
			return
		}
	}
}

func (c *Control) Close() {
	c.toDie <- struct{}{}
	log.WithField("time", time.Now().UnixNano()).Infoln("control closing")
	return
}

func (c *Control) IsClosed() bool {
	select {
	case <-c.die:
		return true
	default:
		return false
	}
}

func (c *Control) moderator() {
	_ = <-c.toDie
	log.WithFields(log.Fields{"ClientId": c.ClientID.Hex()}).Infoln("client going to close")
	close(c.die)
	c.tunnelLock.Lock()
	for _, t := range c.tunnels {
		t.Close()
	}
	c.tunnelLock.Unlock()
	idle := c.idlePipes
	for {
		if idle == nil {
			break
		}
		if !idle.pipe.IsClosed() {
			atomic.AddInt64(&c.totalPipes, -1)
			idle.pipe.Close()
		}
		idle = idle.next
	}
	busy := c.busyPipes
	for {
		if busy == nil {
			break
		}
		if !busy.pipe.IsClosed() {
			atomic.AddInt64(&c.totalPipes, -1)
			busy.pipe.Close()
		}
		busy = busy.next
	}
	c.ctlConn.Close()
}

func (c *Control) recvLoop() {
	atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
	for {
		if c.IsClosed() {
			return
		}
		mType, body, err := msg.ReadMsgWithoutTimeout(c.ctlConn)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "client_Id": c.ClientID.Hex()}).Warningln("ReadMsgWithoutTimeout in recvLoop failed")
			c.Close()
			return
		}

		atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
		switch mType {
		case msg.TypeAddTunnels:
			go c.ServerAddTunnels(body.(*msg.AddTunnels))
		case msg.TypePong:
		case msg.TypePing:
			c.writeChan <- writeReq{msg.TypePong, nil}
		}
	}
}

func (c *Control) writeLoop() {
	lastWrite := time.Now()
	idx := 0
	for {
		if c.IsClosed() {
			return
		}
		select {
		case msgBody := <-c.writeChan:
			if msgBody.mType == msg.TypePing || msgBody.mType == msg.TypePong {
				if time.Now().Before(lastWrite.Add(pingInterval / 2)) {
					continue
				}
			}
			if msgBody.mType == msg.TypePipeReq {
				idx++
			}
			lastWrite = time.Now()
			err := msg.WriteMsg(c.ctlConn, msgBody.mType, msgBody.body)
			if err != nil {
				log.WithFields(log.Fields{"mType": msgBody.mType, "body": fmt.Sprintf("%v", msgBody.body), "client_id": c.ClientID.Hex(), "err": err}).Warningln("send msg to client failed!")
				c.Close()
				return
			}
		case <-c.die:
			return
		}
	}

}

func (c *Control) Serve() {
	go c.moderator()
	go c.recvLoop()
	go c.writeLoop()
	go c.pipeManage()

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if (uint64(time.Now().UnixNano()) - atomic.LoadUint64(&c.lastRead)) > uint64(pingTimeout) {
				log.WithFields(log.Fields{"client_id": c.ClientID.Hex()}).Warningln("recv client ping time out!")
				c.Close()
				return
			}
			select {
			case c.writeChan <- writeReq{msg.TypePing, nil}:
			case <-c.die:
				return
			}
		case <-c.die:
			return
		}
	}
}

func proxyConn(userConn net.Conn, c *Control, tunnelName string) {
	defer userConn.Close()
	p := c.getPipe()
	if p == nil {
		return
	}
	stream, err := p.OpenStream(tunnelName)
	if err != nil {
		c.putPipe(p)
		return
	}
	defer stream.Close()
	c.putPipe(p)
	p1die := make(chan struct{})
	p2die := make(chan struct{})
	go func() {
		io.Copy(stream, userConn)
		close(p1die)
	}()
	go func() {
		io.Copy(userConn, stream)
		close(p2die)
	}()
	select {
	case <-p1die:
	case <-p2die:
	}
	return
}

//add or update tunnel stat
func (c *Control) ServerAddTunnels(sstm *msg.AddTunnels) {
	for name, _ := range sstm.Tunnels {
		if c.IsClosed() {
			return
		}
		var lis net.Listener = nil
		var err error
		c.tunnelLock.Lock()
		oldTunnel, isok := c.tunnels[name]
		if isok {
			oldTunnel.Close()
			delete(c.tunnels, name)
		}
		c.tunnelLock.Unlock()
		tunnelConfig := sstm.Tunnels[name]
		selfHost := false
		if tunnelConfig.Hostname == "" {
			tunnelConfig.Hostname = serverConf.ServerDomain
			selfHost = true
		}
		if tunnelConfig.Protocol == "tcp" || tunnelConfig.Protocol == "udp" {
			lis, err = net.Listen(tunnelConfig.Protocol, fmt.Sprintf("%s:%d", serverConf.ListenIP, tunnelConfig.RemotePort))
			if err != nil {
				log.WithFields(log.Fields{"remote_addr": tunnelConfig.RemoteAddr(), "client_id": c.ClientID.Hex()}).Warningln("forbidden,remote port already in use")
				c.writeChan <- writeReq{msg.TypeError, msg.Error{fmt.Sprintf("add tunnels failed!forbidden,remote addrs(%s) already in use", tunnelConfig.RemoteAddr())}}
				continue
			}
			go func(tunnelName string) {
				for {
					if c.IsClosed() {
						return
					}
					conn, err := lis.Accept()
					if err != nil {
						return
					}
					go proxyConn(conn, c, tunnelName)
				}
			}(name)
			//todo: port should  allocated and managed by server not by OS
			addr := lis.Addr().(*net.TCPAddr)
			tunnelConfig.RemotePort = uint16(addr.Port)
		} else if tunnelConfig.Protocol == "http" || tunnelConfig.Protocol == "https" {
			if tunnelConfig.Subdomain == "" && selfHost {
				subDomain := util.Int2Short(atomic.AddUint64(&subDomainIdx, 1))
				tunnelConfig.Subdomain = string(subDomain)
			}
			if tunnelConfig.Protocol == "http" {
				tunnelConfig.RemotePort = serverConf.HttpPort
			} else {
				tunnelConfig.RemotePort = serverConf.HttpsPort
			}
		}
		tunnel := Tunnel{tunnelConfig: tunnelConfig, listener: lis, ctl: c, tunnelName: name}
		TunnelMapLock.Lock()
		_, isok = TunnelMap[tunnelConfig.RemoteAddr()]
		if isok {
			TunnelMapLock.Unlock()
			log.WithFields(log.Fields{"remote_addr": tunnelConfig.RemoteAddr(), "client_id": c.ClientID.Hex()}).Warningln("forbidden,remote addrs already in use")
			c.writeChan <- writeReq{msg.TypeError, msg.Error{fmt.Sprintf("add tunnels failed!forbidden,remote addrs(%s) already in use", tunnelConfig.RemoteAddr())}}
			continue
		}
		TunnelMap[tunnelConfig.RemoteAddr()] = &tunnel
		TunnelMapLock.Unlock()
		c.tunnelLock.Lock()
		c.tunnels[name] = &tunnel
		c.tunnelLock.Unlock()
		sstm.Tunnels[name] = tunnelConfig

		if serverConf.NotifyEnable {
			err = contrib.AddMember(serverConf.ServerDomain, tunnelConfig.RemoteAddr())
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("notify add member failed!")
			}
		}
	}
	c.writeChan <- writeReq{msg.TypeAddTunnels, *sstm}
	return
}

func (c *Control) GenerateClientId() crypto.UUID {
	c.ClientID = crypto.GenUUID()
	return c.ClientID
}

func (c *Control) ServerHandShake() error {
	var shello msg.ControlServerHello
	var chello *msg.ControlClientHello
	mType, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "msg.ReadMsg")
	}
	if mType != msg.TypeControlClientHello {
		return errors.Errorf("invalid msg type(%d),expect(%d)", mType, msg.TypeControlClientHello)
	}
	chello = body.(*msg.ControlClientHello)
	if serverConf.AuthEnable {
		isok, err := contrib.Auth(chello.AuthToken)
		if err != nil {
			return errors.Wrap(err, "contrib.Auth")
		}
		if !isok {
			return errors.Errorf("auth failed!token:%s", chello.AuthToken)
		}
	}

	if c.encryptMode != "none" {
		priv, keyMsg := crypto.GenerateKeyExChange()
		if keyMsg == nil || priv == nil {
			return errors.Errorf("crypto.GenerateKeyExChange error ,exchange key is nil")
		}
		preMasterSecret, err := crypto.ProcessKeyExchange(priv, chello.CipherKey)
		if err != nil {
			return errors.Wrap(err, "crypto.ProcessKeyExchange")
		}
		c.preMasterSecret = preMasterSecret
		shello.CipherKey = keyMsg
	}
	shello.ClientID = c.GenerateClientId()
	err = msg.WriteMsg(c.ctlConn, msg.TypeControlServerHello, shello)
	if err != nil {
		return errors.Wrap(err, "Write ClientId")
	}

	ControlMapLock.Lock()
	ControlMap[c.ClientID] = c
	ControlMapLock.Unlock()
	return nil
}

func PipeHandShake(conn net.Conn, phs *msg.PipeClientHello) error {
	ControlMapLock.RLock()
	ctl := ControlMap[phs.ClientID]
	ControlMapLock.RUnlock()
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	var err error
	var sess *smux.Session
	if ctl.encryptMode != "none" {
		prf := crypto.NewPrf12()
		var masterKey []byte = make([]byte, 16)
		prf(masterKey, ctl.preMasterSecret, phs.ClientID[:], phs.Once[:])
		cryptoConn, err := crypto.NewCryptoConn(conn, masterKey)
		if err != nil {
			return errors.Wrap(err, "crypto.NewCryptoConn")
		}
		//server endpoint is the pipe connection source,so we use smux.Client
		sess, err = smux.Client(cryptoConn, smuxConfig)
		if err != nil {
			return errors.Wrap(err, "smux.Client")
		}
	} else {
		sess, err = smux.Client(conn, smuxConfig)
		if err != nil {
			return errors.Wrap(err, "smux.Client")
		}
	}
	ctl.putPipe(sess)
	atomic.AddInt64(&ctl.totalPipes, 1)
	return nil
}
