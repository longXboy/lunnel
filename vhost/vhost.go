// Copyright 2016 fatedier, fatedier@gmail.com
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

package vhost

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/longXboy/Lunnel/util"

	"github.com/pkg/errors"
)

const (
	typeClientHello uint8 = 1 // Type client hello
)

// TLS extension numbers
const (
	extensionServerName          uint16 = 0
	extensionStatusRequest       uint16 = 5
	extensionSupportedCurves     uint16 = 10
	extensionSupportedPoints     uint16 = 11
	extensionSignatureAlgorithms uint16 = 13
	extensionALPN                uint16 = 16
	extensionSCT                 uint16 = 18
	extensionSessionTicket       uint16 = 35
	extensionNextProtoNeg        uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo   uint16 = 0xff01
)

type sharedConn struct {
	net.Conn
	sync.Mutex
	buff *bytes.Buffer
}

// the bytes you read in io.Reader, will be reserved in sharedConn
func newShareConn(conn net.Conn) (*sharedConn, io.Reader) {
	sc := &sharedConn{
		Conn: conn,
		buff: bytes.NewBuffer(make([]byte, 0, 1024)),
	}
	return sc, io.TeeReader(conn, sc.buff)
}

func (sc *sharedConn) Read(p []byte) (n int, err error) {
	sc.Lock()
	if sc.buff == nil {
		sc.Unlock()
		return sc.Conn.Read(p)
	}
	sc.Unlock()
	n, err = sc.buff.Read(p)

	if err == io.EOF {
		sc.Lock()
		sc.buff = nil
		sc.Unlock()
		var n2 int
		n2, err = sc.Conn.Read(p[n:])

		n += n2
	}
	return
}

func (sc *sharedConn) WriteBuff(buffer []byte) (err error) {
	sc.buff.Reset()
	_, err = sc.buff.Write(buffer)
	return err
}

func readHandshake(rd io.Reader) (host string, err error) {
	data := util.GetBuf(1024)
	origin := data
	defer util.PutBuf(origin)
	length, err := rd.Read(data)
	if err != nil {
		return
	} else {
		if length < 47 {
			err = errors.Errorf("readHandshake: proto length[%d] is too short", length)
			return
		}
	}
	data = data[:length]
	if uint8(data[5]) != typeClientHello {
		err = errors.Errorf("readHandshake: type[%d] is not clientHello", uint16(data[5]))
		return
	}

	// session
	sessionIdLen := int(data[43])
	if sessionIdLen > 32 || len(data) < 44+sessionIdLen {
		err = errors.Errorf("readHandshake: sessionIdLen[%d] is long", sessionIdLen)
		return
	}
	data = data[44+sessionIdLen:]
	if len(data) < 2 {
		err = errors.Errorf("readHandshake: dataLen[%d] after session is short", len(data))
		return
	}

	// cipher suite numbers
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		err = errors.Errorf("readHandshake: dataLen[%d] after cipher suite is short", len(data))
		return
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		err = errors.Errorf("readHandshake: cipherSuiteLen[%d] is long", cipherSuiteLen)
		return
	}

	// compression method
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		err = errors.Errorf("readHandshake: compressionMethodsLen[%d] is long", compressionMethodsLen)
		return
	}

	data = data[1+compressionMethodsLen:]
	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		err = errors.Errorf("readHandshake: there is no extension data to get servername")
		return
	}
	if len(data) < 2 {
		err = errors.Errorf("readHandshake: extension dataLen[%d] is too short")
		return
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		err = errors.Errorf("readHandshake: extensionsLen[%d] is not equal to dataLen[%d]", extensionsLength, len(data))
		return
	}
	for len(data) != 0 {
		if len(data) < 4 {
			err = errors.Errorf("readHandshake: extensionsDataLen[%d] is too short", len(data))
			return
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			err = errors.Errorf("readHandshake: extensionLen[%d] is long", length)
			return
		}

		switch extension {
		case extensionRenegotiationInfo:
			if length != 1 || data[0] != 0 {
				err = errors.Errorf("readHandshake: extension reNegotiationInfoLen[%d] is short", length)
				return
			}
		case extensionNextProtoNeg:
		case extensionStatusRequest:
		case extensionServerName:
			d := data[:length]
			if len(d) < 2 {
				err = errors.Errorf("readHandshake: remiaining dataLen[%d] is short", len(d))
				return
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				err = errors.Errorf("readHandshake: nameListLen[%d] is not equal to dataLen[%d]", namesLen, len(d))
				return
			}
			for len(d) > 0 {
				if len(d) < 3 {
					err = errors.Errorf("readHandshake: extension serverNameLen[%d] is short", len(d))
					return
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					err = errors.Errorf("readHandshake: nameLen[%d] is not equal to dataLen[%d]", nameLen, len(d))
					return
				}
				if nameType == 0 {
					serverName := string(d[:nameLen])
					host = strings.TrimSpace(serverName)
					return host, nil
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}
	err = errors.Errorf("Unknow error")
	return
}

func GetHttpsHostname(c net.Conn) (sc net.Conn, _ map[string]string, err error) {
	reqInfoMap := make(map[string]string, 0)
	sc, rd := newShareConn(c)
	host, err := readHandshake(rd)
	if err != nil {
		return sc, reqInfoMap, err
	}
	reqInfoMap["Host"] = host
	reqInfoMap["Scheme"] = "https"
	return sc, reqInfoMap, nil
}

func GetHttpRequestInfo(c net.Conn) (_ net.Conn, _ map[string]string, err error) {
	reqInfoMap := make(map[string]string, 0)
	sc, rd := newShareConn(c)

	request, err := http.ReadRequest(bufio.NewReader(rd))
	if err != nil {
		return sc, reqInfoMap, err
	}
	// hostName
	tmpArr := strings.Split(request.Host, ":")
	reqInfoMap["Host"] = tmpArr[0]
	reqInfoMap["Path"] = request.URL.Path
	reqInfoMap["Scheme"] = request.URL.Scheme

	// Authorization
	authStr := request.Header.Get("Authorization")
	if authStr != "" {
		reqInfoMap["Authorization"] = authStr
	}
	request.Body.Close()
	return sc, reqInfoMap, nil
}
