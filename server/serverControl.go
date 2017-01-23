package main

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/xtaci/smux"
)

var minPipes int = 2
var maxPipes int = 16
var maxIdlePipes int = 3
var maxStreams int = 4

var pingInterval time.Duration = time.Second * 8
var pingTimeout time.Duration = time.Second * 13

var ControlMapLock sync.RWMutex
var ControlMap = make(map[crypto.UUID]*Control)

func NewControl(conn net.Conn) *Control {
	ctl := &Control{
		ctlConn:   conn,
		pipeGet:   make(chan *smux.Session),
		pipeAdd:   make(chan *smux.Session),
		die:       make(chan struct{}),
		toDie:     make(chan struct{}),
		writeChan: make(chan writeReq, 128),
	}

	return ctl
}

type writeReq struct {
	mType msg.MsgType
	body  interface{}
}

type Tunnel struct {
	tunnelInfo msg.Tunnel
	listener   net.Listener
}

type pipeNode struct {
	prev *pipeNode
	next *pipeNode
	pipe *smux.Session
}

type Control struct {
	ctlConn         net.Conn
	tunnels         []Tunnel
	preMasterSecret []byte
	lastRead        uint64

	busyPipes *pipeNode
	idleCount int
	idlePipes *pipeNode
	pipeAdd   chan *smux.Session
	pipeGet   chan *smux.Session

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
	println("add idle:", pipe)

}

func (c *Control) addBusyPipe(pipe *smux.Session) {
	pNode := &pipeNode{pipe: pipe, prev: nil, next: nil}
	if c.busyPipes != nil {
		c.busyPipes.prev = pNode
		pNode.next = c.busyPipes
	}
	c.busyPipes = pNode
	println("add busy:", pipe)
}

func (c *Control) removeIdleNode(pNode *pipeNode) {
	if pNode.prev == nil {
		c.idlePipes = pNode.next
	} else {
		pNode.prev.next = pNode.next
		if pNode.next != nil {
			pNode.next.prev = pNode.prev
		}
	}
	c.idleCount--
	println("remove idle:", pNode.pipe)
}

func (c *Control) removeBusyNode(pNode *pipeNode) {
	if pNode.prev == nil {
		c.busyPipes = pNode.next
	} else {
		pNode.prev.next = pNode.next
		if pNode.next != nil {
			pNode.next.prev = pNode.prev
		}
	}
	println("remove busy:", pNode.pipe)
}

func (c *Control) putPipe(p *smux.Session) {
	select {
	case c.pipeAdd <- p:
	case <-c.die:
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

func (c *Control) printNodes() {

}

func (c *Control) clean() {
	busy := c.busyPipes
	for {
		if busy == nil {
			break
		}
		temp := busy.next
		if busy.pipe.IsClosed() {
			c.removeBusyNode(busy)
		} else if busy.pipe.NumStreams() < maxStreams {
			c.removeBusyNode(busy)
			c.addIdlePipe(busy.pipe)
		}
		busy = temp
	}
	idle := c.idlePipes
	for {
		if idle == nil {
			return
		}
		temp := idle.next
		if idle.pipe.IsClosed() {
			c.removeIdleNode(idle)
		} else if idle.pipe.NumStreams() == 0 && c.idleCount > maxIdlePipes {
			fmt.Println("closing pipe!!!count:", c.idleCount)
			c.removeIdleNode(idle)
			idle.pipe.Close()
		}
		idle = temp
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
			temp := idle.next
			c.removeIdleNode(idle)
			idle = temp
		} else {
			c.removeIdleNode(idle)
			return
		}
	}
	return
}

var cleanInterval time.Duration = time.Second * 5

func (c *Control) pipeManage() {
	var available *smux.Session
	ticker := time.NewTicker(cleanInterval)
	defer ticker.Stop()
	for {
		if available == nil || available.IsClosed() {
			available = nil
			idle := c.getIdleFast()
			if idle == nil {
				c.clean()
				idle := c.getIdleFast()
				c.writeChan <- writeReq{msg.TypePipeReq, nil}
				if idle == nil {
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
						}
					}
				} else {
					available = idle.pipe
				}
			} else {
				available = idle.pipe
			}
		}
		fmt.Println("num stream:", available.NumStreams())
	Available:
		select {
		case <-ticker.C:
			c.clean()
		case c.pipeGet <- available:
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
	fmt.Println("control close")
	select {
	case c.toDie <- struct{}{}:
	default:
	}
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
	fmt.Println("!!!!to die!!!!!!!")
	close(c.die)
	for _, t := range c.tunnels {
		t.listener.Close()
	}
	idle := c.idlePipes
	for {
		if idle == nil {
			break
		}
		if !idle.pipe.IsClosed() {
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
		mType, _, err := msg.ReadMsg(c.ctlConn)
		if err != nil {
			c.Close()
			return
		}

		atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
		switch mType {
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
				fmt.Println("req pipe:", idx)
			}
			lastWrite = time.Now()
			err := msg.WriteMsg(c.ctlConn, msgBody.mType, msgBody.body)
			if err != nil {
				fmt.Println("write error:", err.Error())
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

func (c *Control) ServerSyncTunnels(serverDomain string) error {
	_, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "ReadMsg sstm")
	}
	sstm := body.(*msg.SyncTunnels)
	for i := range sstm.Tunnels {
		t := &sstm.Tunnels[i]
		lis, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
		if err != nil {
			return errors.Wrap(err, "binding TCP listener")
		}
		go func() {
			for {
				if c.IsClosed() {
					return
				}
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					p := c.getPipe()
					if p == nil {
						fmt.Println("failed to get pipes!")
						return
					}
					stream, err := p.OpenStream(t.LocalAddress)
					if err != nil {
						c.putPipe(p)
						return
					}
					defer stream.Close()
					c.putPipe(p)
					p1die := make(chan struct{})
					p2die := make(chan struct{})
					go func() {
						io.Copy(stream, conn)
						close(p1die)
					}()
					go func() {
						io.Copy(conn, stream)
						close(p2die)
					}()
					select {
					case <-p1die:
					case <-p2die:
					}
					return
				}()
			}
		}()
		addr := lis.Addr().(*net.TCPAddr)
		t.RemoteAddress = fmt.Sprintf("%s:%d", serverDomain, addr.Port)
		c.tunnels = append(c.tunnels, Tunnel{*t, lis})
	}
	err = msg.WriteMsg(c.ctlConn, msg.TypeSyncTunnels, *sstm)
	if err != nil {
		return errors.Wrap(err, "WriteMsg sstm")
	}
	fmt.Printf("tunnels:%v\n", c.tunnels)
	return nil
}

func (c *Control) GenerateClientId() crypto.UUID {
	c.ClientID = crypto.GenUUID()
	return c.ClientID
}

func (c *Control) ServerHandShake() error {
	_, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		panic(err)
	}
	ckem := body.(*msg.CipherKeyExchange)
	priv, keyMsg := crypto.GenerateKeyExChange()
	if keyMsg == nil || priv == nil {
		return fmt.Errorf("crypto.GenerateKeyExChange error ,exchange key is nil")
	}
	preMasterSecret, err := crypto.ProcessKeyExchange(priv, ckem.CipherKey)
	if err != nil {
		return errors.Wrap(err, "crypto.ProcessKeyExchange")
	}
	fmt.Println(preMasterSecret)
	c.preMasterSecret = preMasterSecret
	var skem msg.CipherKeyExchange
	skem.CipherKey = keyMsg
	err = msg.WriteMsg(c.ctlConn, msg.TypeServerKeyExchange, skem)
	if err != nil {
		return errors.Wrap(err, "write ServerKeyExchange msg")
	}

	var cidm msg.ClientIDExchange
	cidm.ClientID = c.GenerateClientId()
	fmt.Println("client_id:", c.ClientID)
	err = msg.WriteMsg(c.ctlConn, msg.TypeClientID, cidm)
	if err != nil {
		return errors.Wrap(err, "Write ClientId")
	}
	ControlMapLock.Lock()
	ControlMap[c.ClientID] = c
	ControlMapLock.Unlock()
	return nil
}

func PipeHandShake(conn net.Conn) error {
	_, body, err := msg.ReadMsg(conn)
	if err != nil {
		return errors.Wrap(err, "pipe readMsg")
	}
	phs := body.(*msg.PipeHandShake)
	ControlMapLock.RLock()
	ctl := ControlMap[phs.ClientID]
	ControlMapLock.RUnlock()

	prf := crypto.NewPrf12()
	var masterKey []byte = make([]byte, 16)
	prf(masterKey, ctl.preMasterSecret, phs.ClientID[:], phs.Once[:])
	fmt.Println("masterKey:", masterKey)
	cryptoConn, err := crypto.NewCryptoConn(conn, masterKey)
	if err != nil {
		return errors.Wrap(err, "crypto.NewCryptoConn")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	//server endpoint is the pipe connection source,so we use smux.Client
	sess, err := smux.Client(cryptoConn, smuxConfig)
	if err != nil {
		return errors.Wrap(err, "smux.Client")
	}

	ctl.putPipe(sess)
	return nil
}
