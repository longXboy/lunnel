package msg

import (
	"Lunnel/crypto"
	"encoding/json"
	"net"
	"time"

	"github.com/pkg/errors"
)

type MsgType uint8

const (
	TypeControlClientHello MsgType = 1
	TypeClientKeyExchange  MsgType = 2
	TypeServerKeyExchange  MsgType = 3
	TypeClientID           MsgType = 4
	TypePipeClientHello    MsgType = 5
	TypeSyncTunnels        MsgType = 6
	TypePipeReq            MsgType = 7
	TypePing               MsgType = 8
	TypePong               MsgType = 9
)

type ControlClientHello struct {
	EncryptMode string
}

type CipherKeyExchange struct {
	CipherKey []byte
}

type ClientIDExchange struct {
	ClientID crypto.UUID
}

type PipeClientHello struct {
	Once     crypto.UUID
	ClientID crypto.UUID
}

type Tunnel struct {
	Schema        string `json:"Schema"`
	LocalAddress  string `json:"Local"`
	RemoteAddress string `json:"Remote"`
}

type SyncTunnels struct {
	Tunnels []Tunnel
}

func WriteMsg(w net.Conn, mType MsgType, in interface{}) error {
	var length int
	var body []byte
	var err error
	if in == nil {
		length = 0
	} else {
		body, err = json.Marshal(in)
		if err != nil {
			return errors.Wrapf(err, "json marshal %d", mType)
		}
		length = len(body)
		if length > 16777215 {
			return errors.Errorf("write message out of size limit(16777215)")
		}
	}
	x := make([]byte, length+4)
	x[0] = uint8(mType)
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	if body != nil {
		copy(x[4:], body)
	}
	w.SetWriteDeadline(time.Now().Add(time.Second * 10))
	_, err = w.Write(x)
	if err != nil {
		return errors.Wrap(err, "write msg")
	}
	w.SetWriteDeadline(time.Time{})
	return nil
}

func ReadMsgWithoutTimeout(r net.Conn) (MsgType, interface{}, error) {
	return readMsg(r, 0)
}

func ReadMsg(r net.Conn) (MsgType, interface{}, error) {
	return readMsg(r, time.Second*10)
}

func readMsg(r net.Conn, timeout time.Duration) (MsgType, interface{}, error) {
	var header []byte = make([]byte, 4)
	err := readInSize(r, header, timeout)
	if err != nil {
		return 0, nil, errors.Wrap(err, "msg readInSize header")
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	body := make([]byte, length)
	err = readInSize(r, body, timeout)
	if err != nil {
		return 0, nil, errors.Wrap(err, "msg readInSize body")
	}
	var out interface{}
	if MsgType(header[0]) == TypeClientKeyExchange || MsgType(header[0]) == TypeServerKeyExchange {
		out = new(CipherKeyExchange)
	} else if MsgType(header[0]) == TypePipeClientHello {
		out = new(PipeClientHello)
	} else if MsgType(header[0]) == TypeClientID {
		out = new(ClientIDExchange)
	} else if MsgType(header[0]) == TypeSyncTunnels {
		out = new(SyncTunnels)
	} else if MsgType(header[0]) == TypePipeReq || MsgType(header[0]) == TypePing || MsgType(header[0]) == TypePong {
		return MsgType(header[0]), nil, nil
	} else if MsgType(header[0]) == TypeControlClientHello {
		out = new(ControlClientHello)
	} else {
		return 0, nil, errors.Errorf("invalid msg type %d", header[0])
	}
	err = json.Unmarshal(body, out)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "json unmarshal %d", header[0])
	}
	return MsgType(header[0]), out, nil
}

func readInSize(r net.Conn, b []byte, timeout time.Duration) error {
	size := len(b)
	bLeft := b
	remain := size
	for {
		if timeout != 0 {
			r.SetReadDeadline(time.Now().Add(timeout))
		} else {
			r.SetReadDeadline(time.Time{})
		}
		n, err := r.Read(bLeft)
		if err != nil {
			return errors.Wrap(err, "msg readinsize")
		}
		if timeout != 0 {
			r.SetReadDeadline(time.Time{})
		}
		remain = remain - n
		if remain == 0 {
			return nil
		} else {
			bLeft = bLeft[n:]
		}
	}
}
