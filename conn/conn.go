package conn

import (
	"encoding/json"
	"io"
)

var typeKeyExchange uint8 = 16

type KeyExchangeMsg struct {
	ciphertext []byte
}

type Msg struct {
	raw        []byte
	ciphertext []byte
}

func (m *Msg) equal(i interface{}) bool {
	m1, ok := i.(*Msg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ciphertext, m1.ciphertext)
}

func (m *Msg) Marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *Msg) Unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

type Conn struct {
	conn io.ReadWriteCloser
}

func (c *Conn) ReadMsg() (int, interface{}, error) {
	var header [4]byte
	nRead, err := c.readWithSize(header)
	if err != nil {
		return 0, nil, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	body := make([]byte, length)
	err = c.readWithSize(body)
	if err != nil {
		return 0, nil, err
	}
	if header[0] == typeKeyExchange {
		var data KeyExchange
		err = json.Unmarshal(body, &data)
		if err != nil {
			return 0, nil, err
		}
	}
}

func (c *Conn) WriteMsg(body []byte, bodyType int) error {
	length := len(body)
	x := make([]byte, length+4)
	copy(x[4:], m.ciphertext)
	var header [4]byte
	x[0] = bodyType
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	nRead, err := c.conn.Write(x)
	if err != nil {
		return 0, nil, err
	}
}

func (c *Conn) readWithSize(b []byte) error {
	size := len(b)
	bLeft := b
	remain := size
	for {
		n, err := c.Read(bufLeft)
		if err != nil {
			return err
		}
		remain = remain - n
		if remain == 0 {
			break
		} else {
			bLeft = bLeft[n:]
		}
	}
}
