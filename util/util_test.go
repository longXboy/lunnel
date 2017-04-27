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

package util

import (
	"testing"
)

func Test_ParseAddr(t *testing.T) {
	schema, host, port, err := ParseAddr("http://127.0.0.1:")
	if err != nil || schema != "http" || host != "127.0.0.1" || port != 0 {
		t.Error(err, "http://127.0.0.1:", schema, host, port)
	}
	schema, host, port, err = ParseAddr("127.0.0.1")
	if err != nil || schema != "" || host != "127.0.0.1" || port != 0 {
		t.Error(err, "127.0.0.1", schema, host, port)
	}
	schema, host, port, err = ParseAddr("127.0.0.1:80")
	if err != nil || schema != "" || host != "127.0.0.1" || port != 80 {
		t.Error(err, "127.0.0.1:80", schema, host, port)
	}
	schema, host, port, err = ParseAddr("http://127.0.0.1:65535")
	if err != nil || schema != "http" || host != "127.0.0.1" || port != 65535 {
		t.Error(err, "http://127.0.0.1:65535", schema, host, port)
	}
	schema, host, port, err = ParseAddr("unix:///var/run/docker.sock")
	if err != nil || schema != "unix" || host != "/var/run/docker.sock" || port != 0 {
		t.Error(err, "unix:///var/run/docker.sock", schema, host, port)
	}
	schema, host, port, err = ParseAddr("udp://127.0.0.1:123123:")
	if err != nil || schema != "udp" || host != "127.0.0.1:123123" || port != 0 {
		t.Error(err, "udp://127.0.0.1:123123:", schema, host, port)
	}
	schema, host, port, err = ParseAddr("http://:")
	if err != nil || schema != "http" || host != "" || port != 0 {
		t.Error(err, "http://:", schema, host, port)
	}
	schema, host, port, err = ParseAddr("http://:655357")
	if err == nil {
		t.Error(err, "http://:655357", schema, host, port)

	}
}
