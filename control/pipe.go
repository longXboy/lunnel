package control

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"fmt"
	"net"

	"github.com/pkg/errors"
)

var maxStreamNumPerPipe uint = 4

func NewPipe(conn net.Conn) *Pipe {
	return &Pipe{pipeConn: conn}
}

type Pipe struct {
	pipeConn net.Conn

	ID crypto.UUID
}

func (p *Pipe) GenerateUUID() crypto.UUID {
	p.ID = crypto.GenUUID()
	return p.ID
}

func (p *Pipe) Close() error {
	return p.pipeConn.Close()
}

func (p *Pipe) Read() (msg.MsgType, []byte, error) {
	var header []byte = make([]byte, 4)
	err := p.readInSize(header)
	if err != nil {
		return 0, nil, errors.Wrap(err, "Conn readInSize")
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	body := make([]byte, length)
	err = p.readInSize(body)
	if err != nil {
		return 0, nil, errors.Wrap(err, "Conn readInSize")
	}
	return msg.MsgType(header[0]), body, nil
}

func (p *Pipe) Write(mtype msg.MsgType, body []byte) error {
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
	_, err := p.pipeConn.Write(x)
	if err != nil {
		return errors.Wrap(err, "Conn.raw_conn write")
	}
	return nil
}

func (p *Pipe) readInSize(b []byte) error {
	size := len(b)
	bLeft := b
	remain := size
	for {
		n, err := p.pipeConn.Read(bLeft)
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
