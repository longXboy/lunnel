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

package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/longXboy/lunnel/crypto"
	"github.com/longXboy/lunnel/log"
	"github.com/longXboy/lunnel/msg"
	"github.com/longXboy/lunnel/transport"
	"github.com/longXboy/smux"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/net/context"
)

func NewControl(conn net.Conn, encryptMode string, transport string, tunnels map[string]msg.Tunnel, lock *sync.Mutex) *Control {
	ctx, cancel := context.WithCancel(context.Background())

	ctl := &Control{
		ctlConn:       conn,
		writeChan:     make(chan writeReq, 64),
		encryptMode:   encryptMode,
		tunnels:       tunnels,
		transportMode: transport,
		ctx:           ctx,
		cancel:        cancel,
		tunnelsLock:   lock,
	}
	return ctl
}

type writeReq struct {
	mType msg.MsgType
	body  interface{}
}

type Control struct {
	ClientID uuid.UUID

	ctlConn         net.Conn
	tunnelsLock     *sync.Mutex
	tunnels         map[string]msg.Tunnel
	preMasterSecret []byte
	lastRead        uint64
	encryptMode     string
	transportMode   string
	totalPipes      int64

	writeChan chan writeReq
	cancel    context.CancelFunc
	ctx       context.Context
}

func (c *Control) Close() {
	c.cancel()
	log.WithField("time", time.Now().UnixNano()).Debugln("control closing")
	return
}

func (c *Control) createPipe() {
	log.WithFields(log.Fields{"time": time.Now().Unix(), "pipe_count": atomic.LoadInt64(&c.totalPipes)}).Debugln("create pipe to server!")
	pipeConn, err := transport.CreateConn(cliConf.ServerAddr, c.transportMode, cliConf.HttpProxy)
	if err != nil {
		log.WithFields(log.Fields{"addr": cliConf.ServerAddr, "err": err}).Errorln("creating tunnel conn to server failed!")
		return
	}
	defer pipeConn.Close()

	pipe, err := c.pipeHandShake(pipeConn)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Errorln("pipeHandShake failed!")
		return
	}
	defer pipe.Close()
	atomic.AddInt64(&c.totalPipes, 1)
	defer func() {
		log.WithFields(log.Fields{"pipe_count": atomic.LoadInt64(&c.totalPipes)}).Debugln("total pipe count")
		atomic.AddInt64(&c.totalPipes, -1)
	}()
	for {
		if pipe.IsClosed() {
			return
		}
		stream, err := pipe.AcceptStream()
		if err != nil {
			log.WithFields(log.Fields{"err": err, "time": time.Now().Unix(), "client_id": c.ClientID}).Warningln("pipeAcceptStream failed!")
			return
		}
		go func() {
			defer stream.Close()
			c.tunnelsLock.Lock()
			tunnel, isok := c.tunnels[stream.TunnelName()]
			c.tunnelsLock.Unlock()
			if !isok {
				log.WithFields(log.Fields{"name": stream.TunnelName()}).Errorln("can't find tunnel by name")
				return
			}
			var conn net.Conn
			var port uint16 = tunnel.Local.Port
			if tunnel.Local.Schema == "http" || tunnel.Local.Schema == "https" || tunnel.Local.Schema == "tcp" {
				if tunnel.Local.Port == 0 {
					if tunnel.Local.Schema == "https" {
						port = 443
					} else {
						port = 80
					}
				}
				conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", tunnel.Local.Host, port))
				if err != nil {
					log.WithFields(log.Fields{"err": err, "local": tunnel.LocalAddr()}).Warningln("pipe dial local failed!")
					return
				}
				if tunnel.Local.Schema == "https" {
					conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
				}
			} else if tunnel.Local.Schema == "unix" {
				conn, err = net.Dial("unix", tunnel.Local.Host)
				if err != nil {
					log.WithFields(log.Fields{"err": err, "local": tunnel.LocalAddr()}).Warningln("pipe dial local failed!")
					return
				}
			} else {
				if port == 0 {
					log.WithFields(log.Fields{"err": fmt.Sprintf("no port sepicified"), "local": tunnel.LocalAddr()}).Errorln("dial local addr failed!")
					return
				}
				conn, err = net.Dial(tunnel.Local.Schema, fmt.Sprintf("%s:%d", tunnel.Local.Host, port))
				if err != nil {
					log.WithFields(log.Fields{"err": err, "local": tunnel.LocalAddr()}).Warningln("pipe dial local failed!")
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

func (c *Control) SyncTunnels(cstm *msg.AddTunnels) error {
	for k, v := range cstm.Tunnels {
		c.tunnelsLock.Lock()
		t, isok := c.tunnels[k]
		if !isok || t.HttpHostRewrite != v.HttpHostRewrite || t.LocalAddr() != v.LocalAddr() || t.Public.Schema != v.Public.Schema {
			c.tunnels[k] = v
		}
		c.tunnelsLock.Unlock()
		log.WithFields(log.Fields{"local": v.LocalAddr(), "public": v.PublicAddr()}).Infoln("client sync tunnel complete")
	}
	return nil
}

func (c *Control) ClientAddTunnels() error {
	cstm := new(msg.AddTunnels)
	cstm.Tunnels = c.tunnels
	err := msg.WriteMsg(c.ctlConn, msg.TypeAddTunnels, *cstm)
	if err != nil {
		return errors.Wrap(err, "WriteMsg cstm")
	}
	return nil
}

func (c *Control) recvLoop() {
	atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
	for {
		mType, body, err := msg.ReadMsgWithoutTimeout(c.ctlConn)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "client_id": c.ClientID.String()}).Warningln("ReadMsgWithoutTimeout in recv loop failed")
			c.Close()
			return
		}
		log.WithFields(log.Fields{"type": mType, "body": body}).Debugln("recv msg")
		atomic.StoreUint64(&c.lastRead, uint64(time.Now().UnixNano()))
		switch mType {
		case msg.TypePong:
		case msg.TypePing:
			select {
			case c.writeChan <- writeReq{msg.TypePong, nil}:
			default:
				c.Close()
				return
			}
		case msg.TypePipeReq:
			go c.createPipe()
		case msg.TypeAddTunnels:
			c.SyncTunnels(body.(*msg.AddTunnels))
		case msg.TypeError:
			log.Errorln("recv server error:", body.(*msg.Error).Error())
			c.Close()
			return
		case msg.TypeExit:
			log.WithFields(log.Fields{"type": mType, "client_id": c.ClientID}).Warningln("recv msg to exit!")
			os.Exit(1)
			return
		default:
		}
	}
}

func (c *Control) writeLoop() {
	lastWrite := time.Now()
	for {
		select {
		case msgBody := <-c.writeChan:
			if msgBody.mType == msg.TypePing {
				if time.Now().Before(lastWrite.Add(time.Duration(cliConf.Health.Interval * int64(time.Second) / 2))) {
					continue
				}
			}
			log.WithFields(log.Fields{"type": msgBody.mType, "body": msgBody.body}).Debugln("ready to send msg")
			lastWrite = time.Now()
			err := msg.WriteMsg(c.ctlConn, msgBody.mType, msgBody.body)
			if err != nil {
				log.WithFields(log.Fields{"mType": msgBody.mType, "body": fmt.Sprintf("%v", msgBody.body), "client_id": c.ClientID.String(), "err": err}).Warningln("send msg to server failed!")
				c.Close()
				return
			}
		case _ = <-c.ctx.Done():
			return
		}
	}

}

func (c *Control) AddTunnel(w http.ResponseWriter, r *http.Request) {
	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "req body is empty")
		return
	}
	r.Body.Close()

	var addReq msg.AddTunnels
	err = json.Unmarshal(content, &addReq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unmarshal req body failed")
		return
	}
	if len(addReq.Tunnels) > 0 {
		c.tunnelsLock.Lock()
		for k, v := range addReq.Tunnels {
			c.tunnels[k] = v
		}
		c.tunnelsLock.Unlock()
		c.writeChan <- writeReq{msg.TypeAddTunnels, addReq}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (c *Control) serveHttp(lis net.Listener) {
	m := http.NewServeMux()
	m.HandleFunc("/tunnel", c.AddTunnel)
	err := http.Serve(lis, m)
	log.WithFields(log.Fields{"client_id": c.ClientID, "err": err}).Debugln("close http serve")
	c.Close()
}

func (c *Control) Run() {
	defer c.ctlConn.Close()

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", "0.0.0.0", cliConf.ManagePort))
	if err != nil {
		c.Close()
		log.WithFields(log.Fields{"port": cliConf.ManagePort, "err": err}).Fatalln("listen manage port failed!")
		return
	}
	defer lis.Close()

	go c.recvLoop()
	go c.writeLoop()
	go c.serveHttp(lis)

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer signal.Reset(syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	ticker := time.NewTicker(time.Duration(cliConf.Health.Interval * int64(time.Second)))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if (uint64(time.Now().UnixNano()) - atomic.LoadUint64(&c.lastRead)) > uint64(cliConf.Health.TimeOut*int64(time.Second)) {
				log.WithFields(log.Fields{"client_id": c.ClientID.String()}).Warningln("recv server ping time out!")
				c.Close()
				return
			}
			select {
			case c.writeChan <- writeReq{msg.TypePing, nil}:
			default:
				c.Close()
				return
			}
		case s := <-sigChan:
			log.WithFields(log.Fields{"signal": s.String(), "client_id": c.ClientID.String()}).Infoln("got signal to stop")
			select {
			case c.writeChan <- writeReq{msg.TypeExit, nil}:
			default:
				os.Exit(1)
				return
			}
			time.Sleep(time.Millisecond * 250)
			os.Exit(1)
			return
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Control) clientHandShake() error {
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
	if clientId != nil {
		ckem.ClientID = clientId
	}
	err := msg.WriteMsg(c.ctlConn, msg.TypeControlClientHello, ckem)
	if err != nil {
		return errors.Wrap(err, "WriteMsg ckem")
	}

	mType, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "read ClientID")
	}
	if mType == msg.TypeError {
		err := body.(*msg.Error)
		return errors.Wrap(err, "read ClientID")
	}
	csh := body.(*msg.ControlServerHello)
	c.ClientID = csh.ClientID

	clientId = &csh.ClientID

	if cliConf.Durable && cliConf.DurableFile != "" {
		idFile, err := os.OpenFile(cliConf.DurableFile, os.O_CREATE|os.O_WRONLY, os.ModePerm)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "path": cliConf.DurableFile}).Warningln("open file failed")
		} else {
			n, err := idFile.WriteString(clientId.String())
			if err != nil || n != len(clientId.String()) {
				log.WithFields(log.Fields{"err": err, "content": clientId.String(), "nwrite": n}).Warningln("write file failed!")
			}
		}
		idFile.Close()
	}
	if len(csh.CipherKey) > 0 {
		preMasterSecret, err := crypto.ProcessKeyExchange(priv, csh.CipherKey)
		if err != nil {
			return errors.Wrap(err, "crypto.ProcessKeyExchange")
		}
		c.preMasterSecret = preMasterSecret
	}
	return nil
}

func (c *Control) pipeHandShake(conn net.Conn) (*smux.Session, error) {
	var phs msg.PipeClientHello
	phs.Once = uuid.NewV4()
	phs.ClientID = c.ClientID
	err := msg.WriteMsg(conn, msg.TypePipeClientHello, phs)
	if err != nil {
		return nil, errors.Wrap(err, "write pipe handshake")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	var mux *smux.Session
	var underlyingConn io.ReadWriteCloser
	if c.encryptMode != "none" {
		prf := crypto.NewPrf12()
		var masterKey []byte = make([]byte, 16)
		prf(masterKey, c.preMasterSecret, c.ClientID[:], phs.Once[:])
		underlyingConn, err = crypto.NewCryptoStream(conn, masterKey)
		if err != nil {
			return nil, errors.Wrap(err, "crypto.NewCryptoConn")
		}
	} else {
		underlyingConn = conn
	}
	if cliConf.EnableCompress {
		underlyingConn = transport.NewCompStream(underlyingConn)
	}
	mux, err = smux.Server(underlyingConn, smuxConfig)
	if err != nil {
		return nil, errors.Wrap(err, "smux.Server")
	}
	return mux, nil
}
