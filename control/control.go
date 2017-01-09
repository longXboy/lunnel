package control

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"Lunnel/proto"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pkg/errors"
)

type Options struct {
	Tunnels []proto.Tunnel
}

type Proto uint8

const (
	ProtoTCP      Proto = 0
	ProtoUDP      Proto = 1
	ProtoHTTP     Proto = 2
	ProtoHTTPS    Proto = 3
	ProtoUnixSock Proto = 4
)

var maxPipes int = 8
var maxIdlePipes int = 4

var ControlMapLock sync.RWMutex
var ControlMap = make(map[crypto.UUID]*Control)

func NewControl(conn net.Conn, opt *Options) *Control {
	ctl := &Control{ctlConn: conn}
	if opt != nil {
		ctl.tunnels = opt.Tunnels
	}
	return ctl
}

type Control struct {
	ctlConn         net.Conn
	idle            []*Pipe
	idleLock        sync.RWMutex
	tunnels         []proto.Tunnel
	preMasterSecret []byte
	ClientID        crypto.UUID
}

func (c *Control) GenerateClientId() crypto.UUID {
	c.ClientID = crypto.GenUUID()
	return c.ClientID
}

func (c *Control) Close() error {
	return c.ctlConn.Close()
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

func (c *Control) getPipe() *Pipe {
	var temp *Pipe
	c.idleLock.RLock()
	if len(c.idle) > 0 {
		temp = c.idle[len(c.idle)-1]
	}
	c.idleLock.RUnlock()
	return temp
}

func (c *Control) putPipe(p *Pipe) bool {
	isPut := true
	c.idleLock.RLock()
	if len(c.idle) < maxIdlePipes {
		c.idle = append(c.idle, p)
	} else {
		isPut = false
	}
	c.idleLock.RUnlock()
	return isPut
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
		go func() error {
			idx := 0
			for {
				conn, err := lis.Accept()
				if err != nil {
					return errors.Wrap(err, "lis.Accept")
				}
				idx++
				go func() error {
					defer conn.Close()
					fmt.Println("open stream:", idx)
					p := c.getPipe()
					p.Lock.Lock()
					stream, err := p.GetStream(t.LocalAddress)
					if err != nil {
						p.Lock.Unlock()
						return errors.Wrap(err, "p.GetStream")
					}
					defer stream.Close()
					if p.StreamsNum() < 8 {
						c.putPipe(p)
					}
					p.Lock.Unlock()

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
					return nil
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
