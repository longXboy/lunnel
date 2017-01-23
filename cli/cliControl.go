package main

import (
	"Lunnel/crypto"
	"Lunnel/msg"
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
var pingTimeout time.Duration = time.Second * 13

func NewControl(conn net.Conn, opt *Options) *Control {
	ctl := &Control{
		ctlConn:   conn,
		die:       make(chan struct{}),
		toDie:     make(chan struct{}),
		writeChan: make(chan writeReq, 128),
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

	die       chan struct{}
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
	case <-c.die:
		return true
	default:
		return false
	}
}

func (c *Control) moderator() {
	_ = <-c.toDie
	fmt.Println("to die")
	close(c.die)
	c.ctlConn.Close()
}

func (c *Control) createPipe() {
	pipeConn, err := CreateConn("www.longxboy.com:8081", true)
	if err != nil {
		panic(err)
	}
	defer pipeConn.Close()

	pipe, err := c.pipeHandShake(pipeConn)
	if err != nil {
		pipeConn.Close()
		panic(err)
	}
	defer pipe.Close()

	idx := 0
	for {
		if c.IsClosed() {
			return
		}
		if pipe.IsClosed() {
			return
		}
		stream, err := pipe.AcceptStream()
		if err != nil {
			fmt.Println("pipe accept stream error", err)
			return
		}
		idx++
		go func() {
			defer stream.Close()

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
			}()
			go func() {
				io.Copy(conn, stream)
				close(p2die)
			}()
			select {
			case <-p1die:
			case <-p2die:
			}
		}()
	}
	fmt.Println("deleting pipe!!")
}

func (c *Control) ClientSyncTunnels() error {
	cstm := new(msg.SyncTunnels)
	cstm.Tunnels = c.tunnels
	err := msg.WriteMsg(c.ctlConn, msg.TypeSyncTunnels, *cstm)
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
		case msg.TypePipeReq:
			go c.createPipe()
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
			fmt.Println(time.Now().UnixNano(), "  write:", msgBody.mType)

			lastWrite = time.Now()
			err := msg.WriteMsg(c.ctlConn, msgBody.mType, msgBody.body)
			if err != nil {
				fmt.Println("write error:", err.Error())
				c.Close()
				return
			}
		case _ = <-c.die:
			return
		}
	}

}
func (c *Control) Run() {
	go c.moderator()
	go c.recvLoop()
	go c.writeLoop()

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
			case _ = <-c.die:
				return
			}
		case <-c.die:
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

func (c *Control) pipeHandShake(conn net.Conn) (*smux.Session, error) {
	var phs msg.PipeHandShake
	phs.Once = crypto.GenUUID()
	phs.ClientID = c.ClientID
	err := msg.WriteMsg(conn, msg.TypePipeHandShake, phs)
	if err != nil {
		return nil, errors.Wrap(err, "write pipe handshake")
	}
	prf := crypto.NewPrf12()
	var masterKey []byte = make([]byte, 16)
	prf(masterKey, c.preMasterSecret, c.ClientID[:], phs.Once[:])
	fmt.Println("masterKey:", masterKey)
	cryptoConn, err := crypto.NewCryptoConn(conn, masterKey)
	if err != nil {
		return nil, errors.Wrap(err, "crypto.NewCryptoConn")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	mux, err := smux.Server(cryptoConn, smuxConfig)
	if err != nil {
		return nil, errors.Wrap(err, "smux.Server")
	}
	return mux, nil
}
