package pipe

import (
	"Lunnel/crypto"
	"Lunnel/msg"
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

type Options struct {
	Tunnels []msg.Tunnel
}

var maxStreams int = 6
var minPipes int = 2
var maxPipes int = 16
var maxIdlePipes int = 4
var pingInterval time.Duration = time.Second * 8
var pingTimeout time.Duration = time.Second * 21

var ControlMapLock sync.RWMutex
var ControlMap = make(map[crypto.UUID]*Control)

func NewControl(conn net.Conn, opt *Options) *Control {
	ctl := &Control{
		ctlConn:   conn,
		pipeReq:   make(chan chan *Pipe),
		pipeReady: make(chan *Pipe),
		dying:     make(chan struct{}),
		toDie:     make(chan struct{}),
		writeChan: make(chan writeReq),
	}
	if opt != nil {
		ctl.tunnels = opt.Tunnels
	}
	return ctl
}

type writeReq struct {
	mType msg.MsgType
	body  interface{}
}

type Control struct {
	ctlConn         net.Conn
	tunnels         []msg.Tunnel
	pipes           []*Pipe
	preMasterSecret []byte
	lastRead        uint64

	pipeReq   chan chan *Pipe
	pipeReady chan *Pipe
	dying     chan struct{}
	toDie     chan struct{}
	rmPipe    chan *Pipe
	rmTunnel  chan *msg.Tunnel
	writeChan chan writeReq

	ClientID crypto.UUID
}

func (c *Control) GenerateClientId() crypto.UUID {
	c.ClientID = crypto.GenUUID()
	return c.ClientID
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

func (c *Control) createPipe() {
	pipeConn, err := CreateConn("www.longxboy.com:8081", true)
	if err != nil {
		panic(err)
	}
	pipe := NewPipe(pipeConn, c)
	defer pipe.Close()
	pipe.ClientHandShake()

	cryptoConn, err := crypto.NewCryptoConn(pipeConn, pipe.MasterKey)
	if err != nil {
		panic(err)
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	mux, err := smux.Server(cryptoConn, smuxConfig)
	if err != nil {
		panic(err)
		return
	}
	idx := 0
	for {
		if c.IsClosed() {
			return
		}
		stream, err := mux.AcceptStream()
		if err != nil {
			panic(err)
			return
		}
		idx++
		go func() {
			defer stream.Close()
			fmt.Println("open stream:", idx)
			conn, err := net.Dial("tcp", stream.Tunnel())
			if err != nil {
				panic(err)
			}
			defer conn.Close()
			p1die := make(chan struct{})
			p2die := make(chan struct{})

			go func() {
				io.Copy(stream, conn)
				close(p1die)
				fmt.Println("dst copy done:", idx)
			}()
			go func() {
				io.Copy(conn, stream)
				close(p2die)
				fmt.Println("src copy done:", idx)
			}()
			select {
			case <-p1die:
			case <-p2die:
			}
			fmt.Println("close Stream:", idx)

		}()
	}
}

func (c *Control) getPipe(ch chan *Pipe) *Pipe {
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

func (c *Control) putPipe(p *Pipe) {
	select {
	case c.pipeReady <- p:
	case _ = <-c.dying:
		return
	}
	return
}

func (c *Control) ClientSyncTunnels() error {
	cstm := new(msg.SyncTunnels)
	cstm.Tunnels = c.tunnels
	err := msg.WriteMsg(c.ctlConn, msg.TypeSyncTunnel, *cstm)
	if err != nil {
		return errors.Wrap(err, "WriteMsg cstm")
	}
	_, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "ReadMsg cstm")
	}
	cstm = body.(*msg.SyncTunnels)
	c.tunnels = cstm.Tunnels
	fmt.Printf("tunnels:%v\n", c.tunnels)
	return nil
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
			var ch chan *Pipe
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

func (c *Control) Run() {
	go c.moderator()

	ticker := time.NewTicker(pingInterval)
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
		case _ = <-c.pipeReq:
			go c.createPipe()
		case _ = <-c.dying:
			return
		}
	}
}

func (c *Control) Serve() {
	go c.moderator()

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
			idlePipe := idles.Get().(*Pipe)
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
				reqCh := reqWaits.Get().(chan *Pipe)
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
			pipeChan := make(chan *Pipe)
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
	}
	c.tunnels = sstm.Tunnels
	err = msg.WriteMsg(c.ctlConn, msg.TypeSyncTunnel, *sstm)
	if err != nil {
		return errors.Wrap(err, "WriteMsg sstm")
	}
	fmt.Printf("tunnels:%v\n", c.tunnels)
	return nil
}

func (c *Control) ClientHandShake() error {
	priv, keyMsg := crypto.GenerateKeyExChange()
	if keyMsg == nil || priv == nil {
		return fmt.Errorf("GenerateKeyExChange error,key is nil")
	}
	var ckem msg.CipherKeyExchange
	ckem.CipherKey = keyMsg
	err := msg.WriteMsg(c.ctlConn, msg.TypeClientKeyExchange, ckem)
	if err != nil {
		return errors.Wrap(err, "WriteMsg ckem")
	}
	_, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "read skem")
	}
	var preMasterSecret []byte
	skem := body.(*msg.CipherKeyExchange)
	preMasterSecret, err = crypto.ProcessKeyExchange(priv, skem.CipherKey)
	if err != nil {
		return errors.Wrap(err, "crypto.ProcessKeyExchange")
	}
	fmt.Println(preMasterSecret)
	c.preMasterSecret = preMasterSecret

	_, body, err = msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "read ClientID")
	}
	cidm := body.(*msg.ClientIDExchange)

	c.ClientID = cidm.ClientID
	fmt.Println("client_id:", c.ClientID)

	return nil
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
