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

package msg

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type MsgType uint8

const (
	TypeClientHello MsgType = iota
	TypeServerHello
	TypeControlClientHello
	TypeControlServerHello
	TypePipeClientHello
	TypeAddTunnels
	TypePipeReq
	TypePing
	TypePong
	TypeError
	TypeExit
)

type Error struct {
	Msg string
}

func (e *Error) Error() string {
	return e.Msg
}

type ClientHello struct {
	EncryptMode    string
	EnableCompress bool
	Version        string
}

type ControlClientHello struct {
	CipherKey []byte
	AuthToken string
	ClientID  *uuid.UUID
}

type ControlServerHello struct {
	ClientID  uuid.UUID
	CipherKey []byte
}

type PipeClientHello struct {
	Once     uuid.UUID
	ClientID uuid.UUID
}

type Public struct {
	Schema          string
	Host            string
	Port            uint16
	AllowReallocate bool
}

type Local struct {
	Schema             string
	Host               string
	Port               uint16
	InsecureSkipVerify bool
}

type Tunnel struct {
	Public          Public
	Local           Local
	HttpHostRewrite string
}

func (tc Tunnel) PublicAddr() string {
	return fmt.Sprintf("%s://%s:%d", tc.Public.Schema, tc.Public.Host, tc.Public.Port)
}

func (tc Tunnel) LocalAddr() string {
	if tc.Local.Port == 0 {
		return fmt.Sprintf("%s://%s", tc.Local.Schema, tc.Local.Host)
	} else {
		return fmt.Sprintf("%s://%s:%d", tc.Local.Schema, tc.Local.Host, tc.Local.Port)
	}
}

type AddTunnels struct {
	Tunnels map[string]Tunnel
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
	w.SetWriteDeadline(time.Now().Add(time.Second * 12))
	_, err = w.Write(x)
	if err != nil {
		return errors.Wrap(err, "write msg")
	}
	w.SetWriteDeadline(time.Time{})
	return nil
}

func ReadMsgWithoutDeadline(r net.Conn) (MsgType, interface{}, error) {
	return readMsg(r)
}

func ReadMsg(r net.Conn) (MsgType, interface{}, error) {
	r.SetReadDeadline(time.Now().Add(time.Second * 12))
	t, o, e := readMsg(r)
	r.SetReadDeadline(time.Time{})
	return t, o, e
}

func readMsg(r net.Conn) (MsgType, interface{}, error) {
	var header []byte = make([]byte, 4)

	_, err := io.ReadFull(r, header)
	if err != nil {
		return 0, nil, errors.Wrap(err, "io.ReadFull header")
	}

	var out interface{}
	if MsgType(header[0]) == TypeControlClientHello {
		out = new(ControlClientHello)
	} else if MsgType(header[0]) == TypeControlServerHello {
		out = new(ControlServerHello)
	} else if MsgType(header[0]) == TypePipeClientHello {
		out = new(PipeClientHello)
	} else if MsgType(header[0]) == TypeAddTunnels {
		out = new(AddTunnels)
	} else if MsgType(header[0]) == TypePipeReq || MsgType(header[0]) == TypePing || MsgType(header[0]) == TypePong || MsgType(header[0]) == TypeServerHello || MsgType(header[0]) == TypeExit {
		return MsgType(header[0]), nil, nil
	} else if MsgType(header[0]) == TypeClientHello {
		out = new(ClientHello)
	} else if MsgType(header[0]) == TypeError {
		out = new(Error)
	} else {
		return 0, nil, errors.Errorf("invalid msg type %d", header[0])
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > 0 {
		body := make([]byte, length)
		_, err = io.ReadFull(r, body)
		if err != nil {
			return 0, nil, errors.Wrap(err, "io.ReadFull body")
		}
		err = json.Unmarshal(body, out)
		if err != nil {
			return 0, nil, errors.Wrapf(err, "json unmarshal %d", header[0])
		}
	}
	return MsgType(header[0]), out, nil
}
