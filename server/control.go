package main

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"Lunnel/pipe"
	"Lunnel/util"
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
var maxIdlePipes int = 4
var maxStreams = 6

var pingInterval time.Duration = time.Second * 8
var pingTimeout time.Duration = time.Second * 21

var ControlMapLock sync.RWMutex
var ControlMap = make(map[crypto.UUID]*Control)

func NewControl(conn net.Conn) *Control {
	ctl := &Control{
		ctlConn:   conn,
		pipeReq:   make(chan chan *pipe.Pipe),
		pipeReady: make(chan *pipe.Pipe),
		dying:     make(chan struct{}),
		toDie:     make(chan struct{}),
		writeChan: make(chan writeReq),
	}

	return ctl
}

type writeReq struct {
	mType msg.MsgType
	body  interface{}
}

type Tunnel struct {
	msg.Tunnel
	lis net.Listener
}

type Control struct {
	ctlConn         net.Conn
	tunnels         []Tunnel
	pipes           []*pipe.Pipe
	preMasterSecret []byte
	lastRead        uint64

	pipeReq   chan chan *pipe.Pipe
	pipeReady chan *pipe.Pipe
	dying     chan struct{}
	toDie     chan struct{}
	rmPipe    chan *pipe.Pipe
	rmTunnel  chan *Tunnel
	writeChan chan writeReq

	ClientID crypto.UUID
}

func (c *Control) Close() {
	select {
	case c.toDie <- struct{}{}:
	default:
	}
	return
}

func (c *Control) IsClosed() bool {
	select {
	case <-c.dying:
		return true
	default:
		return false
	}
}

func (c *Control) moderator() {
	_ = <-c.toDie
	close(c.dying)
	c.ctlConn.Close()
}

func (c *Control) getPipe(ch chan *pipe.Pipe) *pipe.Pipe {
	select {
	case c.pipeReq <- ch:
	case _ = <-c.dying:
		return nil
	}
	select {
	case pipe := <-ch:
		return pipe
	case _ = <-c.dying:
		return nil
	}
}

func (c *Control) putPipe(p *pipe.Pipe) {
	select {
	case c.pipeReady <- p:
	case _ = <-c.dying:
		return
	}
	return
}

func (c *Control) recvLoop() {
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
		case msg.TypePipeReq:
			var ch chan *pipe.Pipe
			select {
			case c.pipeReq <- ch:
			case _ = <-c.dying:
				return
			}
		}
	}
}

func (c *Control) writeLoop() {
	lastWrite := time.Now()
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

			lastWrite = time.Now()
			err := msg.WriteMsg(c.ctlConn, msgBody.mType, msgBody.body)
			if err != nil {
				c.Close()
				return
			}
		case _ = <-c.dying:
			return
		}
	}

}

func (c *Control) Serve() {
	go c.moderator()
	go c.recvLoop()
	go c.writeLoop()

	//if pipeReq wait num is out of waitQueue size,we drop the req
	reqWaits := util.NewLoopQueue(128)
	idles := util.NewLoopQueue(maxIdlePipes)

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case _ = <-ticker.C:
			if (uint64(time.Now().UnixNano()) - atomic.LoadUint64(&c.lastRead)) > uint64(pingTimeout) {
				c.Close()
				return
			}
			select {
			case c.writeChan <- writeReq{msg.TypePing, nil}:
			case _ = <-c.dying:
				return
			}
		case reqCh := <-c.pipeReq:
			idlePipe := idles.Get().(*pipe.Pipe)
			if idlePipe == nil {
				if reqWaits.Put(reqCh) {
					select {
					case c.writeChan <- writeReq{msg.TypePipeReq, nil}:
					case _ = <-c.dying:
						return
					}
				} else {
					select {
					case reqCh <- nil:
					case _ = <-c.dying:
						return
					}
				}
			} else {
				select {
				case reqCh <- idlePipe:
				case _ = <-c.dying:
					return
				}
			}
		case ready := <-c.pipeReady:
			if ready.StreamsNum() < maxStreams {
				reqCh := reqWaits.Get().(chan *pipe.Pipe)
				if reqCh == nil {
					if !ready.IsIdle {
						if !idles.Put(ready) {
							ready.Close()
						} else {
							ready.IsIdle = true
						}
					}
				} else {
					select {
					case reqCh <- ready:
					case _ = <-c.dying:
						return
					}
				}
			} else if ready.StreamsNum() == maxStreams {
				ready.IsIdle = false
			} else {
				panic("ready pipe's streams num is out of limitaion")
			}
		case _ = <-c.dying:
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
			idx := 0
			pipeChan := make(chan *pipe.Pipe)
			defer close(pipeChan)
			for {
				if c.IsClosed() {
					return
				}
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				idx++
				go func() {
					defer conn.Close()
					fmt.Println("open stream:", idx)
					p := c.getPipe(pipeChan)
					if p == nil {
						fmt.Println("failed to get pipes!")
						return
					}
					defer c.putPipe(p)
					stream, err := p.GetStream(t.LocalAddress)
					if err != nil {
						return
					}
					defer stream.Close()
					c.putPipe(p)

					p1die := make(chan struct{})
					p2die := make(chan struct{})
					go func() {
						io.Copy(stream, conn)
						close(p1die)
						fmt.Println("src copy done:", idx)
					}()
					go func() {
						io.Copy(conn, stream)
						close(p2die)
						fmt.Println("dst copy done:", idx)
					}()
					select {
					case <-p1die:
					case <-p2die:
					}
					fmt.Println("close Stream:", idx)
					return
				}()
			}
		}()
		addr := lis.Addr().(*net.TCPAddr)
		t.RemoteAddress = fmt.Sprintf("%s:%d", serverDomain, addr.Port)
		c.tunnels = append(c.tunnels, Tunnel{*t, lis})
	}
	err = msg.WriteMsg(c.ctlConn, msg.TypeSyncTunnel, *sstm)
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
	h := body.(*msg.PipeHandShake)
	p := pipe.NewPipe(conn, nil)
	p.ID = h.PipeID

	ControlMapLock.RLock()
	ctl := ControlMap[h.ClientID]
	ControlMapLock.RUnlock()

	prf := crypto.NewPrf12()
	var masterKey []byte = make([]byte, 16)
	uuid := make([]byte, 16)
	for i := range uuid {
		uuid[i] = h.PipeID[i]
	}
	fmt.Println("uuid:", uuid)
	prf(masterKey, ctl.preMasterSecret, []byte(fmt.Sprintf("%d", h.ClientID)), uuid)
	p.MasterKey = masterKey
	fmt.Println("masterKey:", masterKey)

	cryptoConn, err := crypto.NewCryptoConn(conn, p.MasterKey)
	if err != nil {
		return errors.Wrap(err, "crypto.NewCryptoConn")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	sess, err := smux.Client(cryptoConn, smuxConfig)
	if err != nil {
		return errors.Wrap(err, "smux.Client")
	}
	p.SetSess(sess)

	ctl.putPipe(p)
	return nil
}
