package msg

import (
	"Lunnel/crypto"
	"Lunnel/proto"
	"encoding/json"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

type MsgType uint8

const (
	TypeClientKeyExchange MsgType = 1
	TypeServerKeyExchange MsgType = 2
	TypeClientID          MsgType = 3
	TypePipeHandShake     MsgType = 4
	TypeSyncTunnel        MsgType = 5
	TypePipeReq           MsgType = 6
	TypePing              MsgType = 7
	TypePong              MsgType = 8
)

type CipherKeyExchange struct {
	CipherKey []byte
}

type ClientIDExchange struct {
	ClientID crypto.UUID
}

type PipeHandShake struct {
	PipeID   crypto.UUID
	ClientID crypto.UUID
}

type SyncTunnels struct {
	Tunnels []proto.Tunnel
}

func WriteMsg(w io.Writer, mType MsgType, in interface{}) error {
	body, err := json.Marshal(in)
	if err != nil {
		return errors.Wrapf(err, "json marshal %d", mType)
	}
	length := len(body)
	if length > 16777215 {
		return fmt.Errorf("write message out of size limit(16777215)")
	}
	x := make([]byte, length+4)
	x[0] = uint8(mType)
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], body)
	_, err = w.Write(x)
	if err != nil {
		return errors.Wrap(err, "write msg")
	}
	return nil
}

func ReadMsg(r io.Reader) (MsgType, interface{}, error) {
	var header []byte = make([]byte, 4)
	err := readInSize(r, header)
	if err != nil {
		return 0, nil, errors.Wrap(err, "msg readInSize header")
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	body := make([]byte, length)
	err = readInSize(r, body)
	if err != nil {
		return 0, nil, errors.Wrap(err, "msg readInSize body")
	}
	var out interface{}
	if MsgType(header[0]) == TypeClientKeyExchange || MsgType(header[0]) == TypeServerKeyExchange {
		out = new(CipherKeyExchange)
	} else if MsgType(header[0]) == TypePipeHandShake {
		out = new(PipeHandShake)
	} else if MsgType(header[0]) == TypeClientID {
		out = new(ClientIDExchange)
	} else if MsgType(header[0]) == TypeSyncTunnel {
		out = new(SyncTunnels)
	} else if MsgType(header[0]) == TypePipeReq || MsgType(header[0]) == TypePing || MsgType(header[0]) == TypePong {
		return MsgType(header[0]), nil, nil
	} else {
		return 0, nil, fmt.Errorf("invalid msg type %d", header[0])
	}
	err = json.Unmarshal(body, out)
	fmt.Println("read msg:", out)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "json unmarshal %d", header[0])
	}
	return MsgType(header[0]), out, nil
}

func readInSize(r io.Reader, b []byte) error {
	size := len(b)
	bLeft := b
	remain := size
	for {
		n, err := r.Read(bLeft)
		if err != nil {
			return errors.Wrap(err, "msg readinsize")
		}
		remain = remain - n
		if remain == 0 {
			return nil
		} else {
			bLeft = bLeft[n:]
		}
	}
}
