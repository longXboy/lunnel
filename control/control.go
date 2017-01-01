package control

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
)

var currentClientID uint64 = 0
var maxPipeNumPerControl uint = 8

var ControlMapLock sync.RWMutex
var ControlMap = make(map[uint64]*Control, 3000)

func NewControl(conn net.Conn) *Control {
	return &Control{controlConn: conn}
}

type Control struct {
	controlConn net.Conn
	pipes       []Pipe

	PreMasterSecret []byte
	ClientID        uint64
}

func (c *Control) GenerateClientId() uint64 {
	c.ClientID = atomic.AddUint64(&currentClientID, 1)
	return c.ClientID
}

func (c *Control) Close() error {
	return c.controlConn.Close()
}

func (c *Control) readMsg() (msg.MsgType, []byte, error) {
	var header []byte = make([]byte, 4)
	err := c.readInSize(header)
	if err != nil {
		return 0, nil, errors.Wrap(err, "Conn readInSize")
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	body := make([]byte, length)
	err = c.readInSize(body)
	if err != nil {
		return 0, nil, errors.Wrap(err, "Conn readInSize")
	}
	return msg.MsgType(header[0]), body, nil
}

func (c *Control) writeMsg(mtype msg.MsgType, body []byte) error {
	length := len(body)
	if length > 16777215 {
		return fmt.Errorf("write message out of size limit(16777215)")
	}
	x := make([]byte, length+4)
	x[0] = uint8(mtype)
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], body)
	_, err := c.controlConn.Write(x)
	if err != nil {
		return errors.Wrap(err, "Conn.raw_conn write")
	}
	return nil
}

func (c *Control) readInSize(b []byte) error {
	size := len(b)
	bLeft := b
	remain := size
	for {
		n, err := c.controlConn.Read(bLeft)
		if err != nil {
			return errors.Wrap(err, "Conn.raw_conn read")
		}
		remain = remain - n
		if remain == 0 {
			return nil
		} else {
			bLeft = bLeft[n:]
		}
	}
}

func (c *Control) ClientHandShake() error {
	priv, keyMsg := crypto.GenerateKeyExChange()
	if keyMsg == nil || priv == nil {
		return fmt.Errorf("GenerateKeyExChange error,key is nil")
	}
	var ckem msg.CipherKey = keyMsg
	message, err := json.Marshal(ckem)
	if err != nil {
		return errors.Wrap(err, "marshal ckem")
	}
	err = c.writeMsg(msg.TypeClientKeyExchange, message)
	if err != nil {
		return errors.Wrap(err, "Write ckem")
	}
	mType, body, err := c.readMsg()
	if err != nil {
		return errors.Wrap(err, "read skem")
	}
	var preMasterSecret []byte
	if mType == msg.TypeServerKeyExchange {
		var skem msg.CipherKey
		err = json.Unmarshal(body, &skem)
		if err != nil {
			return errors.Wrap(err, "Unmarshal skem")
		}
		preMasterSecret, err = crypto.ProcessKeyExchange(priv, skem)
		if err != nil {
			return errors.Wrap(err, "crypto.ProcessKeyExchange")
		}
		fmt.Println(preMasterSecret)
		c.PreMasterSecret = preMasterSecret
	} else {
		return fmt.Errorf("invalid msg type expect:%v recv:%v", msg.TypeServerKeyExchange, mType)
	}
	mType, body, err = c.readMsg()
	if err != nil {
		return errors.Wrap(err, "read ClientID")
	}

	if mType == msg.TypeClientID {
		var cidm msg.ClientID
		err = json.Unmarshal(body, &cidm)
		if err != nil {
			return errors.Wrap(err, "Unmarshal ClientId")
		}
		c.ClientID = uint64(cidm)
		fmt.Println("client_id:", c.ClientID)
	} else {
		return fmt.Errorf("invalid msg type expect:%v recv:%v", msg.TypeClientID, mType)
	}
	return nil
}

func (c *Control) ServerHandShake() error {
	mType, body, err := c.readMsg()
	if err != nil {
		panic(err)
	}
	if mType == msg.TypeClientKeyExchange {
		var ckem msg.CipherKey
		err = json.Unmarshal(body, &ckem)
		if err != nil {
			return errors.Wrap(err, "Unmarshal KeyExchangeMsg")
		}
		priv, keyMsg := crypto.GenerateKeyExChange()
		if keyMsg == nil || priv == nil {
			return fmt.Errorf("crypto.GenerateKeyExChange error ,exchange key is nil")
		}
		preMasterSecret, err := crypto.ProcessKeyExchange(priv, ckem)
		if err != nil {
			return errors.Wrap(err, "crypto.ProcessKeyExchange")
		}
		fmt.Println(preMasterSecret)
		c.PreMasterSecret = preMasterSecret
		var skem msg.CipherKey = keyMsg
		message, err := json.Marshal(skem)
		if err != nil {
			return errors.Wrap(err, "marshal KeyExchangeMsg")
		}
		err = c.writeMsg(msg.TypeServerKeyExchange, message)
		if err != nil {
			return errors.Wrap(err, "write ServerKeyExchange msg")
		}

		var cidm msg.ClientID = msg.ClientID(c.GenerateClientId())
		message, err = json.Marshal(cidm)
		if err != nil {
			return errors.Wrap(err, "Marshal ClientId")
		}
		fmt.Println("client_id:", c.ClientID)
		err = c.writeMsg(msg.TypeClientID, message)
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
