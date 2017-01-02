package control

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
)

var currentClientID uint64 = 0
var maxPipes uint = 8
var maxIdlePipes uint = 4

var ControlMapLock sync.RWMutex
var ControlMap = make(map[uint64]*Control, 2000)

func NewControl(conn net.Conn) *Control {
	return &Control{ctlConn: conn}
}

type Control struct {
	ctlConn  net.Conn
	busy     []*Pipe
	busyLock sync.RWMutex
	idle     []*Pipe
	idleLock sync.RWMutex

	PreMasterSecret []byte
	ClientID        uint64
}

func (c *Control) GenerateClientId() uint64 {
	c.ClientID = atomic.AddUint64(&currentClientID, 1)
	return c.ClientID
}

func (c *Control) Close() error {
	return c.ctlConn.Close()
}

func (c *Control) ClientHandShake() error {
	priv, keyMsg := crypto.GenerateKeyExChange()
	if keyMsg == nil || priv == nil {
		return fmt.Errorf("GenerateKeyExChange error,key is nil")
	}
	var ckem msg.CipherKey = keyMsg

	err := msg.WriteMsg(c.ctlConn, msg.TypeClientKeyExchange, ckem)
	if err != nil {
		return errors.Wrap(err, "WriteMsg ckem")
	}
	mType, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "read skem")
	}
	var preMasterSecret []byte
	if mType == msg.TypeServerKeyExchange {
		skem := body.(*msg.CipherKey)
		preMasterSecret, err = crypto.ProcessKeyExchange(priv, *skem)
		if err != nil {
			return errors.Wrap(err, "crypto.ProcessKeyExchange")
		}
		fmt.Println(preMasterSecret)
		c.PreMasterSecret = preMasterSecret
	} else {
		return fmt.Errorf("invalid msg type expect:%v recv:%v", msg.TypeServerKeyExchange, mType)
	}

	mType, body, err = msg.ReadMsg(c.ctlConn)
	if err != nil {
		return errors.Wrap(err, "read ClientID")
	}
	fmt.Println("interface:", body)
	if mType == msg.TypeClientID {
		cidm := body.(*msg.ClientID)

		c.ClientID = uint64(*cidm)
		fmt.Println("client_id:", c.ClientID)
	} else {
		return fmt.Errorf("invalid msg type expect:%v recv:%v", msg.TypeClientID, mType)
	}
	return nil
}

func (c *Control) ServerHandShake() error {
	mType, body, err := msg.ReadMsg(c.ctlConn)
	if err != nil {
		panic(err)
	}
	if mType == msg.TypeClientKeyExchange {
		ckem := body.(*msg.CipherKey)
		priv, keyMsg := crypto.GenerateKeyExChange()
		if keyMsg == nil || priv == nil {
			return fmt.Errorf("crypto.GenerateKeyExChange error ,exchange key is nil")
		}
		preMasterSecret, err := crypto.ProcessKeyExchange(priv, *ckem)
		if err != nil {
			return errors.Wrap(err, "crypto.ProcessKeyExchange")
		}
		fmt.Println(preMasterSecret)
		c.PreMasterSecret = preMasterSecret
		var skem msg.CipherKey = keyMsg

		err = msg.WriteMsg(c.ctlConn, msg.TypeServerKeyExchange, skem)
		if err != nil {
			return errors.Wrap(err, "write ServerKeyExchange msg")
		}

		var cidm msg.ClientID = msg.ClientID(c.GenerateClientId())
		fmt.Println("client_id:", c.ClientID)
		err = msg.WriteMsg(c.ctlConn, msg.TypeClientID, cidm)
		if err != nil {
			return errors.Wrap(err, "Write ClientId")
		}
		ControlMapLock.Lock()
		ControlMap[c.ClientID] = c
		ControlMapLock.Unlock()

	} else {
		return fmt.Errorf("invalid msg type expect:%v recv:%v", msg.TypeClientKeyExchange, mType)
	}
	return nil
}
