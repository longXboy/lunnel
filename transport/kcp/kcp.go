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

package kcp

import (
	"net"
	"runtime"

	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go"
)

var (
	noDelay        = 1
	interval       = 40
	resend         = 0
	noCongestion   = 1
	SockBuf        = 1194304
	dataShard      = 10
	parityShard    = 3
	udpSegmentSize = 1400
	send_wnd       = 128
	recv_wnd       = 512
)

func Dial(addr string) (net.Conn, error) {
	//block, _ := kcp.NewNoneBlockCrypt([]byte{12})
	kcpconn, err := kcp.DialWithOptions(addr, nil, dataShard, parityShard)
	if err != nil {
		return nil, errors.Wrap(err, "create kcpConn")
	}
	kcpconn.SetStreamMode(true)
	kcpconn.SetNoDelay(noDelay, interval, resend, noCongestion)
	kcpconn.SetWindowSize(send_wnd, recv_wnd)
	kcpconn.SetMtu(udpSegmentSize)
	kcpconn.SetACKNoDelay(false)

	if err := kcpconn.SetDSCP(0); err != nil {
		return nil, errors.Wrap(err, "kcpConn SetDSCP")
	}

	if err := kcpconn.SetReadBuffer(SockBuf); err != nil {
		return nil, errors.Wrap(err, "kcpConn SetReadBuffer")
	}
	if err := kcpconn.SetWriteBuffer(SockBuf); err != nil {
		return nil, errors.Wrap(err, "kcpConn SetWriteBuffer")
	}
	return kcpconn, nil
}

type Listener struct {
	lis *kcp.Listener
}

func Listen(addr string) (*Listener, error) {
	//block, _ := kcp.NewNoneBlockCrypt([]byte{12})
	lis, err := kcp.ListenWithOptions(addr, nil, dataShard, parityShard)
	if err != nil {
		return nil, errors.Wrap(err, "kcp ListenWithOptions")
	}
	//can't set dscp with multi interfaces in mac os x
	if lis.Addr().(*net.UDPAddr).IP.String() != "::" || runtime.GOOS != "darwin" {
		if err := lis.SetDSCP(0); err != nil {
			return nil, errors.Wrap(err, "kcp SetDSCP")
		}
	}
	if err := lis.SetReadBuffer(SockBuf); err != nil {
		return nil, errors.Wrap(err, "kcp SetReadBuffer")
	}
	if err := lis.SetWriteBuffer(SockBuf); err != nil {
		return nil, errors.Wrap(err, "kcp SetWriteBuffer")
	}
	return &Listener{lis: lis}, nil
}

func (l *Listener) Close() error {
	return l.lis.Close()
}
func (l *Listener) Addr() net.Addr {
	return l.lis.Addr()
}
func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.lis.AcceptKCP()
	if err != nil {
		return nil, errors.Wrap(err, "kcp AcceptKcp")
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(noDelay, interval, resend, noCongestion)
	conn.SetMtu(udpSegmentSize)
	conn.SetWindowSize(send_wnd, recv_wnd)
	conn.SetACKNoDelay(false)
	return conn, nil
}
