package main

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"Lunnel/pipe"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/xtaci/smux"
)

type Options struct {
	Tunnels []msg.Tunnel
}

var pingInterval time.Duration = time.Second * 8
var pingTimeout time.Duration = time.Second * 21

func NewControl(conn net.Conn, opt *Options) *Control {
	ctl := &Control{
		ctlConn:   conn,
		pipeReq:   make(chan struct{}),
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
	preMasterSecret []byte
	lastRead        uint64

	pipeReq   chan struct{}
	dying     chan struct{}
	toDie     chan struct{}
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

func (c *Control) pipeHandShake(conn net.Conn) (*pipe.Pipe, error) {
	p := pipe.NewPipe(conn)

	uuid := p.GeneratePipeID()
	var uuidm msg.PipeHandShake
	uuidm.PipeID = uuid
	uuidm.ClientID = c.ClientID
	err := msg.WriteMsg(conn, msg.TypePipeHandShake, uuidm)
	if err != nil {
		return nil, errors.Wrap(err, "write pipe handshake")
	}
	prf := crypto.NewPrf12()
	var masterKey []byte = make([]byte, 16)
	uuidmar := make([]byte, 16)
	for i := range uuidm.PipeID {
		uuidmar[i] = uuidm.PipeID[i]
	}
	fmt.Println("uuid:", uuidmar)

	prf(masterKey, c.preMasterSecret, []byte(fmt.Sprintf("%d", c.ClientID)), uuidmar)
	p.MasterKey = masterKey
	fmt.Println("masterKey:", masterKey)

	return p, nil
}

func (c *Control) createPipe() {
	pipeConn, err := CreateConn("www.longxboy.com:8081", true)
	if err != nil {
		panic(err)
	}
	defer pipeConn.Close()

	pipe, err := c.pipeHandShake(pipeConn)
	if err != nil {
		panic(err)
	}

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
			select {
			case c.pipeReq <- struct{}{}:
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
