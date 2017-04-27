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

package transport

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"

	"github.com/longXboy/lunnel/log"
	"github.com/longXboy/lunnel/transport/kcp"
	"github.com/pkg/errors"
)

func Listen(addr string, transportMode string) (net.Listener, error) {
	var lis net.Listener
	var err error
	if transportMode == "kcp" {
		lis, err = kcp.Listen(addr)
		if err != nil {
			return nil, errors.Wrap(err, "listen kcp")
		}
	} else {
		lis, err = net.Listen("tcp", addr)
		if err != nil {
			log.WithFields(log.Fields{"address": addr, "protocol": "tcp", "err": err}).Fatalln("server's control listen failed!")
			return nil, errors.Wrap(err, "listen tcp")
		}
	}
	return lis, nil
}

func CreateConn(addr string, transportMode string, httpProxy string) (net.Conn, error) {
	var err error
	if transportMode == "kcp" {
		kcpConn, err := kcp.Dial(addr)
		if err != nil {
			return nil, errors.Wrap(err, "kcp dial")
		}
		return kcpConn, nil
	} else {
		if httpProxy == "" {
			tcpConn, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, errors.Wrap(err, "tcp dial")
			}
			return tcpConn, nil
		} else {
			var parsedUrl *url.URL
			parsedUrl, err = url.Parse(httpProxy)
			if err != nil {
				return nil, errors.Wrap(err, "url parse")
			}
			proxyConn, err := net.Dial("tcp", parsedUrl.Host)
			if err != nil {
				return nil, errors.Wrap(err, "http_proxy dial")
			}
			req, err := http.NewRequest("CONNECT", "http://"+addr, nil)
			if err != nil {
				return nil, errors.Wrap(err, "http_proxy dial,generate new req")
			}
			if parsedUrl.User != nil {
				proxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(parsedUrl.User.String()))
				req.Header.Set("Proxy-Authorization", proxyAuth)
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; lunnel)")
			req.Write(proxyConn)
			resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
			if err != nil {
				return nil, errors.Wrap(err, "http_proxy dial,read response")
			}
			content, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, errors.Wrap(err, "http_proxy dial,ioutil read response")
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return nil, errors.New(fmt.Sprintf("http_proxy dial,response code not 200,body:%s", string(content)))
			}
			log.WithFields(log.Fields{"content": string(content), "http_proxy": parsedUrl.Host}).Infoln("connect http_proxy success!")
			return proxyConn, nil
		}
	}
}
