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
	"fmt"
	"testing"
	"time"

	"github.com/pkg/errors"
)

func Test_sockBuf(t *testing.T) {
	SockBuf = 32
	errChan := make(chan error)
	go func() {
		lis, err := Listen("127.0.0.1:8088")
		if err != nil {
			errChan <- errors.Wrapf(err, "server listen")
			return
		}
		defer lis.Close()

		conn, err := lis.Accept()
		if err != nil {
			errChan <- errors.Wrapf(err, "server accept conn failed")
			return
		}
		defer conn.Close()
		var b []byte = make([]byte, 64)
		nRead, err := conn.Read(b)
		if err != nil {
			errChan <- errors.Wrapf(err, "server read conn failed")
			return
		}
		fmt.Println("server read:", string(b))
		if nRead != 64 {
			errChan <- errors.Wrapf(err, "server read size not equal 64")
			return
		}
		for i := range b {
			b[i] = 'b'
		}
		nWrite, err := conn.Write(b)
		if err != nil {
			errChan <- errors.Wrapf(err, "server write conn failed")
			return
		}
		if nWrite != 64 {
			errChan <- errors.Wrapf(err, "server write size not equal 64")
			return
		}
		time.Sleep(time.Second)
	}()
	go func() {
		conn, err := Dial("127.0.0.1:8088")
		if err != nil {
			errChan <- errors.Wrapf(err, "dial server err")
			return
		}
		defer conn.Close()
		var body []byte = make([]byte, 64)
		for i := range body {
			body[i] = 'a'
		}
		nWrite, err := conn.Write(body)
		if err != nil {
			errChan <- errors.Wrapf(err, "client conn write failed!%v", err)
			return
		}
		if nWrite != 64 {
			errChan <- errors.Wrapf(err, "client write size not equal 64")
			return
		}
		var b []byte = make([]byte, 64)
		nRead, err := conn.Read(b)
		if err != nil {
			errChan <- errors.Wrapf(err, "client conn read failed!%v", err)
			return
		}
		if nRead != 64 {
			errChan <- errors.Wrapf(err, "client read size not equal 64")
			return
		}
		close(errChan)
	}()
	for err := range errChan {
		t.Error(err)
		break
	}
	time.Sleep(time.Second * 2)
}
