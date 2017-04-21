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

package vhost

import (
	"fmt"
	"time"

	"github.com/longXboy/lunnel/version"
)

const badGateWayTemplate string = "HTTP/1.1 502 Bad Gateway\r\nServer: lunnel/%s\r\nDate: %s\r\nContent-Length: 35\r\n\r\nBad GateWay: proxy_tunnel_not_found"

func BadGateWayResp() string {
	return fmt.Sprintf(badGateWayTemplate, version.Version, time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
}
