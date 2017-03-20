package main

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"Lunnel/smux"
	"Lunnel/util"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

var pingInterval time.Duration = time.Second * 8
var pingTimeout time.Duration = time.Second * 17

func NewControl(conn net.Conn, encryptMode string) *Control {
	ctl := &Control{
		ctlConn:     conn,
		die:         make(chan struct{}),
		toDie:       make(chan struct{}),
		writeChan:   make(chan writeReq, 128),
		encryptMode: encryptMode,
	}
	ctl.tunnels = cliConf.Tunnels
	return ctl
}

type writeReq struct {
	mType msg.MsgType
	body  interface{}
}

type Control struct {
	ctlConn         net.Conn
	tunnels         map[string]msg.TunnelConfig
	preMasterSecret []byte
	lastRead        uint64
	encryptMode     string

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
	close(c.die)
	c.ctlConn.Close()
}

func (c *Control) createPipe() {
	log.WithField("time", time.Now().Unix()).Infoln("create pipe!")
	pipeConn, err := CreateConn(cliConf.ServerAddr, true)
	if err != nil {
		log.WithFields(log.Fields{"addr": cliConf.ServerAddr, "err": err}).Errorln("creating tunnel conn to server failed!")
		return
	}
	defer pipeConn.Close()

	pipe, err := c.pipeHandShake(pipeConn)
	if err != nil {
		pipeConn.Close()
		log.WithFields(log.Fields{"err": err}).Errorln("pipeHandShake failed!")
		return
	}
	defer pipe.Close()

	for {
		if c.IsClosed() {
			return
		}
		if pipe.IsClosed() {
			return
		}
		stream, err := pipe.AcceptStream()
		if err != nil {
			log.WithFields(log.Fields{"err": err, "time": time.Now().Unix()}).Warningln("pipeAcceptStream failed!")
			return
		}
		go func() {
			defer stream.Close()
			tunnel, isok := c.tunnels[stream.TunnelLocalAddr()]
			if !isok {
				log.WithFields(log.Fields{"name": stream.TunnelLocalAddr()}).Errorln("can't find tunnel by name")
				return
			}
			var conn net.Conn
			localProto, addr := util.SplitAddr(tunnel.LocalAddr)
			if localProto == "http" || localProto == "https" || localProto == "" {
				conn, err = net.Dial("tcp", addr)
				if err != nil {
					log.WithFields(log.Fields{"err": err, "local": stream.TunnelLocalAddr()}).Warningln("pipe dial local failed!")
					return
				}
				if tunnel.Protocol == "https" {
					conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
				}
			} else {
				conn, err = net.Dial(localProto, addr)
				if err != nil {
					log.WithFields(log.Fields{"err": err, "local": stream.TunnelLocalAddr()}).Warningln("pipe dial local failed!")
					return
				}
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
	for _, v := range c.tunnels {
		if v.Protocol == "http" || v.Protocol == "https" {
			log.WithFields(log.Fields{"local": v.LocalAddr, "remote": fmt.Sprintf("%s://%s.%s:%d", v.Protocol, v.Subdomain, v.Hostname, v.RemotePort)}).Infoln("client sync tunnel complete")
		} else {
			log.WithFields(log.Fields{"local": v.LocalAddr, "remote": fmt.Sprintf("%s://%s:%d", v.Protocol, v.Hostname, v.RemotePort)}).Infoln("client sync tunnel complete")
		}
	}
	return nil
}

func (c *Control) recvLoop() {
	atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
	for {
		if c.IsClosed() {
			return
		}
		mType, _, err := msg.ReadMsgWithoutTimeout(c.ctlConn)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Warningln("ReadMsgWithoutTimeout failed")
			c.Close()
			return
		}
		log.WithFields(log.Fields{"mType": mType}).Infoln("recv msg from server")
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
			lastWrite = time.Now()
			err := msg.WriteMsg(c.ctlConn, msgBody.mType, msgBody.body)
			if err != nil {
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
	var ckem msg.ControlClientHello
	var priv []byte
	var keyMsg []byte
	if c.encryptMode != "none" {
		priv, keyMsg = crypto.GenerateKeyExChange()
		if keyMsg == nil || priv == nil {
			return errors.New("GenerateKeyExChange error,key is nil")
		}
		ckem.CipherKey = keyMsg
	}
	ckem.AuthToken = cliConf.AuthToken
	err := msg.WriteMsg(c.ctlConn, msg.TypeControlClientHello, ckem)
	if err != nil {
		return errors.Wrap(err, "WriteMsg ckem")
	}

	_, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "read ClientID")
	}
	cidm := body.(*msg.ControlServerHello)
	c.ClientID = cidm.ClientID
	if len(cidm.CipherKey) > 0 {
		preMasterSecret, err := crypto.ProcessKeyExchange(priv, cidm.CipherKey)
		if err != nil {
			return errors.Wrap(err, "crypto.ProcessKeyExchange")
		}
		c.preMasterSecret = preMasterSecret
	}
	return nil
}

func (c *Control) pipeHandShake(conn net.Conn) (*smux.Session, error) {
	var phs msg.PipeClientHello
	phs.Once = crypto.GenUUID()
	phs.ClientID = c.ClientID
	err := msg.WriteMsg(conn, msg.TypePipeClientHello, phs)
	if err != nil {
		return nil, errors.Wrap(err, "write pipe handshake")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	var mux *smux.Session
	if c.encryptMode != "none" {
		prf := crypto.NewPrf12()
		var masterKey []byte = make([]byte, 16)
		prf(masterKey, c.preMasterSecret, c.ClientID[:], phs.Once[:])
		cryptoConn, err := crypto.NewCryptoConn(conn, masterKey)
		if err != nil {
			return nil, errors.Wrap(err, "crypto.NewCryptoConn")
		}

		mux, err = smux.Server(cryptoConn, smuxConfig)
		if err != nil {
			return nil, errors.Wrap(err, "smux.Server")
		}
	} else {
		mux, err = smux.Server(conn, smuxConfig)
		if err != nil {
			return nil, errors.Wrap(err, "smux.Server")
		}
	}

	return mux, nil
}
