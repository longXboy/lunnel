// Copyright 2017 longXboy, longxboyhi@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"container/list"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/longXboy/lunnel/contrib"
	"github.com/longXboy/lunnel/crypto"
	"github.com/longXboy/lunnel/log"
	"github.com/longXboy/lunnel/msg"
	"github.com/longXboy/lunnel/transport"
	"github.com/longXboy/lunnel/util"
	"github.com/longXboy/smux"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/net/context"
)

var maxIdlePipes uint32
var maxStreams uint64

var cleanInterval time.Duration = time.Second * 60

var ControlMapLock sync.RWMutex
var ControlMap = make(map[uuid.UUID]*Control)

var OldTunnelLock sync.Mutex
var OldTunnelMap = make(map[uuid.UUID]map[string]msg.Tunnel)

var subDomainIdx uint64

var TunnelMapLock sync.RWMutex
var TunnelMap = make(map[string]*Tunnel)

func NewControl(conn net.Conn, encryptMode string, enableCompress bool, version string) *Control {
	ctx, cancel := context.WithCancel(context.Background())

	ctl := &Control{
		ctlConn:        conn,
		pipeGet:        make(chan *smux.Session),
		pipeAdd:        make(chan *smux.Session),
		writeChan:      make(chan writeReq, 64),
		encryptMode:    encryptMode,
		tunnels:        make(map[string]*Tunnel, 0),
		tunnelLock:     new(sync.Mutex),
		enableCompress: enableCompress,
		ctx:            ctx,
		cancel:         cancel,
		version:        version,
		busyPipes:      list.New(),
		idlePipes:      list.New(),
	}
	return ctl
}

type writeReq struct {
	mType msg.MsgType
	body  interface{}
}

type Tunnel struct {
	tunnelConfig msg.Tunnel
	listener     net.Listener
	name         string
	ctl          *Control
	isClosed     bool
}

func (t *Tunnel) Close() {
	if t.isClosed {
		return
	}
	TunnelMapLock.Lock()
	delete(TunnelMap, t.tunnelConfig.PublicAddr())
	TunnelMapLock.Unlock()
	if t.listener != nil {
		t.listener.Close()
	}
	if serverConf.NotifyEnable {
		err := contrib.RemoveTunnel(serverConf.ServerDomain, t.tunnelConfig, t.ctl.ClientID.String())
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("notify remove member failed!")
		}
	}
	t.isClosed = true
	t.listener = nil
}

type Control struct {
	// To work on both ARM and x86-32,
	// these two fields must be the first elements to keep 64-bit
	// alignment for atomic access to the fields.
	lastRead      uint64
	totalPipes    uint32
	idlePipeCount uint32
	busyPipeCount uint32

	ClientID        uuid.UUID
	ctlConn         net.Conn
	preMasterSecret []byte
	encryptMode     string
	enableCompress  bool
	writeChan       chan writeReq
	version         string

	tunnels    map[string]*Tunnel
	tunnelLock *sync.Mutex

	busyPipes *list.List
	idlePipes *list.List
	pipeAdd   chan *smux.Session
	pipeGet   chan *smux.Session

	cancel context.CancelFunc
	ctx    context.Context
}

func (c *Control) putPipe(p *smux.Session) {
	select {
	case c.pipeAdd <- p:
	case <-c.ctx.Done():
		p.Close()
		atomic.AddUint32(&c.totalPipes, ^uint32(0))
		return
	}
	return
}

func (c *Control) getPipe() *smux.Session {
	select {
	case p := <-c.pipeGet:
		return p
	case <-c.ctx.Done():
		return nil
	}
}

func (c *Control) clean() *smux.Session {
	if serverConf.Debug {
		if atomic.LoadUint32(&c.totalPipes) > maxIdlePipes {
			log.WithFields(log.Fields{"total_pipe_count": atomic.LoadUint32(&c.totalPipes), "client_id": c.ClientID.String()}).Debugln("total pipe count")
		}
	}
	var deleted int64 = 0
	front := c.busyPipes.Front()
	next := front
	for {
		if front == nil {
			break
		}
		next = front.Next()
		sess := front.Value.(*smux.Session)
		if sess.IsClosed() {
			deleted++
			c.busyPipes.Remove(front)
		} else if num := uint64(sess.NumStreams()); num < maxStreams {
			if num <= maxStreams/2 {
				c.idlePipes.PushFront(c.busyPipes.Remove(front))
			} else {
				c.idlePipes.PushBack(c.busyPipes.Remove(front))
			}
		}
		front = next
	}
	front = c.idlePipes.Front()
	next = front
	var idle *smux.Session
	for {
		if front == nil {
			break
		}
		next = front.Next()
		sess := front.Value.(*smux.Session)
		if sess.IsClosed() {
			c.idlePipes.Remove(front)
			deleted++
		} else if sess.NumStreams() == 0 && uint32(c.idlePipes.Len()) > maxIdlePipes {
			c.idlePipes.Remove(front)
			deleted++
			sess.Close()
			log.WithFields(log.Fields{"idle_count": c.idlePipes.Len(), "pipe": fmt.Sprintf("%p", sess), "client_id": c.ClientID.String()}).Debugln("remove and close idle")
		} else if idle == nil {
			idle = sess
		}
		front = next
	}
	if deleted > 0 {
		atomic.AddUint32(&c.totalPipes, ^uint32(deleted-1))
	}
	atomic.StoreUint32(&c.busyPipeCount, uint32(c.busyPipes.Len()))
	atomic.StoreUint32(&c.idlePipeCount, uint32(c.idlePipes.Len()))
	return idle
}

func (c *Control) getIdleFast() *smux.Session {
	idle := c.idlePipes.Front()
	for {
		if idle == nil {
			atomic.StoreUint32(&c.idlePipeCount, uint32(c.idlePipes.Len()))
			return nil
		}
		next := idle.Next()
		if idle.Value.(*smux.Session).IsClosed() {
			atomic.AddUint32(&c.totalPipes, ^uint32(0))
			c.idlePipes.Remove(idle)
		} else {
			atomic.StoreUint32(&c.idlePipeCount, uint32(c.idlePipes.Len()))
			return c.idlePipes.Remove(idle).(*smux.Session)
		}
		idle = next
	}
}

func (c *Control) pipeManage() {
	defer log.CapturePanic()
	defer c.closePipes()

	var available *smux.Session
	ticker := time.NewTicker(cleanInterval)
	defer ticker.Stop()
	for {
	Prepare:
		if available == nil || available.IsClosed() {
			if available != nil {
				atomic.AddUint32(&c.totalPipes, ^uint32(0))
			}
			available = c.getIdleFast()
			if available == nil {
				available = c.clean()
				select {
				case c.writeChan <- writeReq{msg.TypePipeReq, nil}:
				default:
					c.Close()
					return
				}
				if available == nil {
					pipeGetTimeout := time.After(time.Second * 12)
					for {
						select {
						case <-ticker.C:
							available = c.clean()
							if available != nil {
								goto Available
							}
						case p := <-c.pipeAdd:
							if !p.IsClosed() {
								if uint64(p.NumStreams()) < maxStreams {
									available = p
									goto Available
								} else {
									c.busyPipes.PushBack(p)
									atomic.StoreUint32(&c.busyPipeCount, uint32(c.busyPipes.Len()))
								}
							} else {
								atomic.AddUint32(&c.totalPipes, ^uint32(0))
							}
						case <-c.ctx.Done():
							return
						case <-pipeGetTimeout:
							goto Prepare
						}
					}
				}
			}
		}
	Available:
		select {
		case <-ticker.C:
			c.clean()
		case c.pipeGet <- available:
			log.WithFields(log.Fields{"pipe": fmt.Sprintf("%p", available), "client_id": c.ClientID.String()}).Debugln("dispatch pipe to consumer")
			available = nil
		case p := <-c.pipeAdd:
			if !p.IsClosed() {
				if num := uint64(p.NumStreams()); num < maxStreams {
					if num <= maxStreams/2 {
						c.idlePipes.PushFront(p)
					} else {
						c.idlePipes.PushBack(p)
					}
					atomic.StoreUint32(&c.idlePipeCount, uint32(c.idlePipes.Len()))
				} else {
					c.busyPipes.PushBack(p)
					atomic.StoreUint32(&c.busyPipeCount, uint32(c.busyPipes.Len()))
				}
			} else {
				atomic.AddUint32(&c.totalPipes, ^uint32(0))
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Control) Close() {
	log.WithField("clientId", c.ClientID).Debugln("ready to close control")
	c.cancel()
}

func (c *Control) closeTunnels() map[string]msg.Tunnel {
	log.WithField("clientId", c.ClientID).Debugln("ready to close tunnels")
	tunnelConfigMap := make(map[string]msg.Tunnel)
	c.tunnelLock.Lock()
	for _, t := range c.tunnels {
		t.Close()
		tunnelConfigMap[t.name] = t.tunnelConfig
	}
	c.tunnelLock.Unlock()
	return tunnelConfigMap
}

func (c *Control) closePipes() {
	idle := c.idlePipes.Front()
	for {
		if idle == nil {
			break
		}
		sess := idle.Value.(*smux.Session)
		if !sess.IsClosed() {
			sess.Close()
		}
		atomic.AddUint32(&c.totalPipes, ^uint32(0))
		idle = idle.Next()
	}
	c.idlePipes = nil

	busy := c.busyPipes.Front()
	for {
		if busy == nil {
			break
		}
		sess := busy.Value.(*smux.Session)
		if !sess.IsClosed() {
			sess.Close()
		}
		atomic.AddUint32(&c.totalPipes, ^uint32(0))
		busy = busy.Next()
	}
	c.busyPipes = nil

	log.WithField("clientId", c.ClientID).Debugln("close pipes")
}

func (c *Control) recvLoop() {
	defer log.CapturePanic()
	defer log.WithField("clientId", c.ClientID).Debugln("close recvLoop")

	atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
	for {
		mType, body, err := msg.ReadMsgWithoutDeadline(c.ctlConn)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "client_Id": c.ClientID.String()}).Warningln("ReadMsgWithoutTimeout in recvLoop failed")
			c.Close()
			return
		}
		if mType != msg.TypePing && mType != msg.TypePong {
			log.WithFields(log.Fields{"type": mType, "body": body, "client_id": c.ClientID}).Debugln("recv msg")
		}
		atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
		switch mType {
		case msg.TypeAddTunnels:
			go c.ServerAddTunnels(body.(*msg.AddTunnels))
		case msg.TypePong:
		case msg.TypePing:
			select {
			case c.writeChan <- writeReq{msg.TypePong, nil}:
			default:
				c.Close()
				return
			}
		case msg.TypeExit:
			c.Close()
			return
		default:
		}
	}
}

func (c *Control) writeLoop() {
	defer log.CapturePanic()
	defer log.WithField("clientId", c.ClientID).Debugln("close writeLoop")

	lastWrite := time.Now()
	idx := 0
	for {
		select {
		case msgBody := <-c.writeChan:
			if msgBody.mType == msg.TypePing {
				if time.Now().Before(lastWrite.Add(time.Duration(serverConf.Health.Interval * int64(time.Second) / 2))) {
					continue
				}
			}
			if msgBody.mType == msg.TypePipeReq {
				idx++
			}
			lastWrite = time.Now()
			if msgBody.mType != msg.TypePing && msgBody.mType != msg.TypePong {
				log.WithFields(log.Fields{"type": msgBody.mType, "body": msgBody.body, "client_id": c.ClientID}).Debugln("ready to send msg")
			}
			err := msg.WriteMsg(c.ctlConn, msgBody.mType, msgBody.body)
			if err != nil {
				log.WithFields(log.Fields{"mType": msgBody.mType, "body": fmt.Sprintf("%v", msgBody.body), "client_id": c.ClientID.String(), "err": err}).Warningln("send msg to client failed!")
				c.Close()
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Control) Serve() {
	defer func() {
		ControlMapLock.Lock()
		ctl, isok := ControlMap[c.ClientID]
		if isok && ctl == c {
			delete(ControlMap, c.ClientID)
		}
		ControlMapLock.Unlock()

		tunnelsMap := c.closeTunnels()
		OldTunnelLock.Lock()
		OldTunnelMap[c.ClientID] = tunnelsMap
		OldTunnelLock.Unlock()
		defer log.WithField("clientId", c.ClientID).Debugln("close mainLoop")
	}()
	defer c.ctlConn.Close()

	go c.recvLoop()
	go c.writeLoop()
	go c.pipeManage()

	ticker := time.NewTicker(time.Duration(serverConf.Health.Interval * int64(time.Second)))
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if (uint64(time.Now().UnixNano()) - atomic.LoadUint64(&c.lastRead)) > uint64(serverConf.Health.TimeOut*int64(time.Second)) {
				log.WithFields(log.Fields{"client_id": c.ClientID.String()}).Warningln("recv client ping time out!")
				c.Close()
				return
			}
			select {
			case c.writeChan <- writeReq{msg.TypePing, nil}:
			default:
				c.Close()
				return
			}
		case <-c.ctx.Done():
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
	//todo:close stream friendly
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
	defer log.CapturePanic()

	c.tunnelLock.Lock()
	defer c.tunnelLock.Unlock()
	for name, tunnel := range sstm.Tunnels {
		var lis net.Listener = nil
		var err error
		oldTunnel, isok := c.tunnels[name]
		if isok {
			oldTunnel.Close()
			delete(c.tunnels, name)
		}

		if tunnel.Public.Schema == "tcp" || tunnel.Public.Schema == "udp" {
			if tunnel.Public.Port == 0 && oldTunnel != nil && tunnel.Public.Schema == oldTunnel.tunnelConfig.Public.Schema && tunnel.LocalAddr() == oldTunnel.tunnelConfig.LocalAddr() {
				tunnel.Public.AllowReallocate = true
				tunnel.Public.Port = oldTunnel.tunnelConfig.Public.Port
			}
			if tunnel.Public.Schema == "udp" {
				addr := net.UDPAddr{
					Port: int(tunnel.Public.Port),
					IP:   net.ParseIP(serverConf.ListenIP),
				}
				udpConn, err := net.ListenUDP("udp", &addr)
				if err != nil {
					if tunnel.Public.AllowReallocate {
						addr.Port = 0
						udpConn, err = net.ListenUDP("udp", &addr)
					}
					if err != nil {
						log.WithFields(log.Fields{"remote_addr": tunnel.PublicAddr(), "client_id": c.ClientID.String(), "err": err.Error()}).Warningln("listen tunnel failed!")
						select {
						case c.writeChan <- writeReq{msg.TypeError, msg.Error{fmt.Sprintf("add tunnels(remote_addr:%s) failed!err:=%s", tunnel.PublicAddr(), err.Error())}}:
						default:
							c.Close()
							return
						}

						continue
					}
				}
				go proxyConn(udpConn, c, name)

				tunnel.Public.Port = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
				tunnel.Public.Host = serverConf.ServerDomain
			} else {
				lis, err = net.Listen(tunnel.Public.Schema, fmt.Sprintf("%s:%d", serverConf.ListenIP, tunnel.Public.Port))
				if err != nil {
					if tunnel.Public.AllowReallocate {
						lis, err = net.Listen(tunnel.Public.Schema, fmt.Sprintf("%s:%d", serverConf.ListenIP, 0))
					}
					if err != nil {
						log.WithFields(log.Fields{"remote_addr": tunnel.PublicAddr(), "client_id": c.ClientID.String(), "err": err.Error()}).Warningln("listen tunnel failed!")
						select {
						case c.writeChan <- writeReq{msg.TypeError, msg.Error{fmt.Sprintf("add tunnels(remote_addr:%s) failed!err:=%s", tunnel.PublicAddr(), err.Error())}}:
						default:
							c.Close()
							return
						}

						continue
					}
				}
				go func(tunnelName string) {
					for {
						conn, err := lis.Accept()
						if err != nil {
							return
						}
						go proxyConn(conn, c, tunnelName)
					}
				}(name)
				//todo: port should  allocated and managed by server not by OS
				addr := lis.Addr().(*net.TCPAddr)
				tunnel.Public.Port = uint16(addr.Port)
				tunnel.Public.Host = serverConf.ServerDomain
			}
		} else if tunnel.Public.Schema == "http" || tunnel.Public.Schema == "https" {
			if tunnel.Public.Host == "" {
				if oldTunnel != nil && tunnel.Public.Schema == oldTunnel.tunnelConfig.Public.Schema && tunnel.LocalAddr() == oldTunnel.tunnelConfig.LocalAddr() {
					tunnel.Public.AllowReallocate = true
					tunnel.Public.Host = oldTunnel.tunnelConfig.Public.Host
				} else {
					subDomain := util.Int2Short(atomic.AddUint64(&subDomainIdx, 1))
					tunnel.Public.Host = fmt.Sprintf("%s.%s", string(subDomain), serverConf.ServerDomain)
				}
			}
			if tunnel.Public.Schema == "http" {
				tunnel.Public.Port = serverConf.HttpPort
			} else {
				tunnel.Public.Port = serverConf.HttpsPort
			}
		}
		tunnelControl := Tunnel{tunnelConfig: tunnel, listener: lis, ctl: c, name: name}
		TunnelMapLock.Lock()
		_, isok = TunnelMap[tunnel.PublicAddr()]
		if isok {
			TunnelMapLock.Unlock()
			if lis != nil {
				lis.Close()
			}
			log.WithFields(log.Fields{"remote_addr": tunnel.PublicAddr(), "client_id": c.ClientID.String()}).Warningln("forbidden,remote addrs already in use")
			select {
			case c.writeChan <- writeReq{msg.TypeError, msg.Error{fmt.Sprintf("add tunnels failed!forbidden,remote addrs(%s) already in use", tunnel.PublicAddr())}}:
			default:
				c.Close()
				return
			}
			continue
		}
		TunnelMap[tunnel.PublicAddr()] = &tunnelControl
		TunnelMapLock.Unlock()
		c.tunnels[name] = &tunnelControl
		sstm.Tunnels[name] = tunnel

		if serverConf.NotifyEnable {
			err = contrib.AddTunnel(serverConf.ServerDomain, tunnel, c.ClientID.String())
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("notify add member failed!")
			}
		}
	}
	select {
	case c.writeChan <- writeReq{msg.TypeAddTunnels, *sstm}:
	default:
		c.Close()
		return
	}
	return
}

func (c *Control) GenerateClientId() uuid.UUID {
	c.ClientID = uuid.NewV4()
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
		isok, err := contrib.Auth(chello)
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
	if chello.ClientID != nil {
		shello.ClientID = *chello.ClientID
	} else {
		shello.ClientID = c.GenerateClientId()
	}
	c.ClientID = shello.ClientID
	err = msg.WriteMsg(c.ctlConn, msg.TypeControlServerHello, shello)
	if err != nil {
		return errors.Wrap(err, "Write ClientId")
	}

	if chello.ClientID != nil {
		ControlMapLock.RLock()
		old, isok := ControlMap[c.ClientID]
		ControlMapLock.RUnlock()
		var oldTunnelsMap map[string]msg.Tunnel
		if isok {
			oldTunnelsMap = old.closeTunnels()
			for name, oldTunnel := range oldTunnelsMap {
				c.tunnels[name] = &Tunnel{isClosed: true, name: name, tunnelConfig: oldTunnel}
			}
		} else {
			OldTunnelLock.Lock()
			oldTunnelsMap, isok = OldTunnelMap[c.ClientID]
			if isok {
				delete(OldTunnelMap, c.ClientID)
			}
			OldTunnelLock.Unlock()
			if isok {
				for name, oldTunnel := range oldTunnelsMap {
					c.tunnels[name] = &Tunnel{isClosed: true, name: name, tunnelConfig: oldTunnel}
				}
			}
		}
	}

	ControlMapLock.Lock()
	ControlMap[c.ClientID] = c
	ControlMapLock.Unlock()

	return nil
}

func PipeHandShake(conn net.Conn, phs *msg.PipeClientHello) error {
	ControlMapLock.RLock()
	ctl, isok := ControlMap[phs.ClientID]
	ControlMapLock.RUnlock()
	if !isok {
		return errors.Errorf("invalid phs.client_id %s", phs.ClientID.String())
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 1194304
	smuxConfig.IdleStreamTimeout = time.Minute * 30
	var err error
	var sess *smux.Session
	var underlyingConn io.ReadWriteCloser
	if ctl.encryptMode != "none" {
		prf := crypto.NewPrf12()
		var masterKey []byte = make([]byte, 16)
		prf(masterKey, ctl.preMasterSecret, phs.ClientID[:], phs.Once[:])
		underlyingConn, err = crypto.NewCryptoStream(conn, masterKey)
		if err != nil {
			return errors.Wrap(err, "crypto.NewCryptoConn")
		}
	} else {
		underlyingConn = conn
	}
	if ctl.enableCompress {
		underlyingConn = transport.NewCompStream(underlyingConn)
	}
	sess, err = smux.Client(underlyingConn, smuxConfig)
	if err != nil {
		return errors.Wrap(err, "smux.Client")
	}
	atomic.AddUint32(&ctl.totalPipes, 1)
	ctl.putPipe(sess)
	return nil
}
