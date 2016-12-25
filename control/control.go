package control

import (
	"Lunnel/msg"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
)

var currentClientId uint64 = 0
var maxPipeNumPerControl uint = 8

var ControlMapLock sync.RWMutex
var ControlMap = make(map[uint64]*Control, 3000)

func NewControlConn(conn net.Conn) *Control {
	return &Control{controlConn: conn}
}

type Control struct {
	controlConn net.Conn
	pipes       []Pipe

	PreMasterSecret []byte
	ClientId        uint64
}

func (c *Control) GenerateClientId() uint64 {
	c.ClientId = atomic.AddUint64(&currentClientId, 1)
	return c.ClientId
}

func (c *Control) Close() error {
	return c.controlConn.Close()
}

func (c *Control) Read() (msg.MsgType, []byte, error) {
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

func (c *Control) Write(mtype msg.MsgType, body []byte) error {
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
