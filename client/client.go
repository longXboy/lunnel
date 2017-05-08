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

package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	rawLog "log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/getsentry/raven-go"
	"github.com/longXboy/lunnel/crypto"
	"github.com/longXboy/lunnel/log"
	"github.com/longXboy/lunnel/msg"
	"github.com/longXboy/lunnel/transport"
	"github.com/longXboy/lunnel/util"
	"github.com/longXboy/lunnel/version"
	"github.com/longXboy/smux"
	"github.com/satori/go.uuid"
)

const reconnectInterval = 8

var clientId *uuid.UUID
var tunnels map[string]msg.Tunnel
var tunnelsLock sync.Mutex

func init() {
	tunnels = make(map[string]msg.Tunnel, 0)
}

func LoadTLSConfig(rootCertPaths []string) (*tls.Config, error) {
	pool := x509.NewCertPool()

	for _, certPath := range rootCertPaths {
		if certPath == "" {
			continue
		}
		rootCrt, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		pemBlock, _ := pem.Decode(rootCrt)
		if pemBlock == nil {
			return nil, fmt.Errorf("Bad PEM data")
		}
		certs, err := x509.ParseCertificates(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(certs[0])
	}

	return &tls.Config{RootCAs: pool}, nil
}

func dialServer(transportMode string) (conn net.Conn, err error) {
	if transportMode == "tcp" {
		log.WithFields(log.Fields{"server tcp address": cliConf.ServerTcpAddr}).Debugln("create conn to server")
		conn, err = transport.CreateTCPConn(cliConf.ServerTcpAddr, cliConf.HttpProxy)
		if err != nil {
			log.WithFields(log.Fields{"server tcp address": cliConf.ServerTcpAddr, "err": err}).Warnln("create conn to server failed!")
			return
		}
	} else {
		log.WithFields(log.Fields{"server udp address": cliConf.ServerUdpAddr}).Debugln("create conn to server")
		conn, err = transport.CreateKCPConn(cliConf.ServerUdpAddr)
		if err != nil {
			log.WithFields(log.Fields{"server udp address": cliConf.ServerUdpAddr, "err": err}).Warnln("create conn to server failed!")
			return
		}
	}
	return
}

func dialAndRun(transportMode string) {
	defer time.Sleep(time.Duration(time.Second * reconnectInterval))

	log.WithFields(log.Fields{"transportMode": transportMode}).Infoln("trying to create control conn to server")
	conn, err := dialServer(transportMode)
	if err != nil {
		return
	}
	defer conn.Close()

	chello := msg.ClientHello{EncryptMode: cliConf.EncryptMode, EnableCompress: cliConf.EnableCompress, Version: version.Version}
	err = msg.WriteMsg(conn, msg.TypeClientHello, chello)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("write ControlClientHello failed!")
		return
	}
	mType, body, err := msg.ReadMsg(conn)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("read server hello failed!")
		return
	}
	if mType == msg.TypeError {
		serverError := body.(*msg.Error)
		log.WithFields(log.Fields{"server error": serverError.Error()}).Errorln("client hello failed!")
		return
	} else if mType == msg.TypeServerHello {
		log.Debugln("recv msg serer hello success")
	}
	var underlyingConn io.ReadWriteCloser
	if cliConf.EncryptMode == "tls" {
		tlsConfig, err := LoadTLSConfig([]string{cliConf.Tls.TrustedCert})
		if err != nil {
			log.WithFields(log.Fields{"trusted cert": cliConf.Tls.TrustedCert, "err": err}).Fatalln("load tls trusted cert failed!")
			return
		}
		tlsConfig.ServerName = cliConf.Tls.ServerName
		underlyingConn = tls.Client(conn, tlsConfig)
	} else if cliConf.EncryptMode == "aes" {
		underlyingConn, err = crypto.NewCryptoStream(conn, []byte(cliConf.Aes.SecretKey))
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("client hello,crypto.NewCryptoConn failed!")
			return
		}
	} else if cliConf.EncryptMode == "none" {
		underlyingConn = conn
	} else {
		log.WithFields(log.Fields{"encrypt_mode": cliConf.EncryptMode, "err": "invalid EncryptMode"}).Errorln("client hello failed!")
		return
	}
	if cliConf.EnableCompress {
		underlyingConn = transport.NewCompStream(underlyingConn)
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	sess, err := smux.Client(underlyingConn, smuxConfig)
	if err != nil {
		underlyingConn.Close()
		log.WithFields(log.Fields{"err": err}).Warnln("upgrade to smux.Client failed!")
		return
	}
	defer sess.Close()
	stream, err := sess.OpenStream("")
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("sess.OpenStream failed!")
		return
	}

	ctl := NewControl(stream, cliConf.EncryptMode, transportMode, tunnels, &tunnelsLock)
	err = ctl.clientHandShake()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("control.ClientHandShake failed!")
		return
	}
	log.WithFields(log.Fields{"client_id": ctl.ClientID.String(), "version": version.Version}).Infoln("server handshake success!")
	err = ctl.ClientAddTunnels()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("control.ClientSyncTunnels failed!")
		return
	}
	ctl.Run()
}

func Main(configDetail []byte, configType string) {
	err := LoadConfig(configDetail, configType)
	if err != nil {
		rawLog.Fatalf("load config failed!err:=%v", err)
	}
	if cliConf.LogFile != "" {
		f, err := os.OpenFile(cliConf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			rawLog.Fatalf("open log file failed!err:=%v\n", err)
			return
		}
		defer f.Close()
		log.Init(cliConf.Debug, f)
	} else {
		log.Init(cliConf.Debug, nil)
	}
	raven.SetDSN(cliConf.DSN)
	defer log.CapturePanic()

	if cliConf.ClientId != "" {
		u, err := uuid.FromString(string(cliConf.ClientId))
		if err != nil {
			log.WithFields(log.Fields{"err": err, "cliConf.ClientId": string(cliConf.ClientId)}).Errorln("unmarshal cliConf.ClientId failed!")
			return
		} else {
			clientId = &u
		}
	} else if cliConf.Durable && cliConf.DurableFile != "" {
		idFile, err := os.OpenFile(cliConf.DurableFile, os.O_RDONLY|os.O_CREATE, os.ModePerm)
		if err != nil {
			rawLog.Fatalf("open log file %s failed!err:=%v\n", cliConf.DurableFile, err)
			return
		}
		content, err := ioutil.ReadAll(idFile)
		if err != nil {
			idFile.Close()
			rawLog.Fatalf("read id file content failed!err:=%v\n", err)
		} else {
			idFile.Close()
		}
		if len(content) > 0 {
			u, err := uuid.FromString(string(content))
			if err != nil {
				log.WithFields(log.Fields{"err": err, "content": string(content)}).Warningln("unmarshal uuid failed!")
			} else {
				clientId = &u
			}
		}
	}

	for name, tc := range cliConf.Tunnels {
		localSchema, localHost, localPort, err := util.ParseAddr(tc.LocalAddr)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Warnln("util.ParseLocalAddr failed!")
			return
		}
		var tunnel msg.Tunnel
		tunnel.HttpHostRewrite = tc.HttpHostRewrite
		tunnel.Local.Schema = localSchema
		tunnel.Local.Host = localHost
		tunnel.Local.InsecureSkipVerify = tc.HttpsSkipVerify
		tunnel.Local.Port = uint16(localPort)
		tunnel.Public.Schema = tc.Schema
		tunnel.Public.Host = tc.Host
		tunnel.Public.Port = tc.Port
		if tunnel.Public.Host == "" && tunnel.Public.Port == 0 {
			tunnel.Public.AllowReallocate = true
		}
		tunnels[name] = tunnel
	}

	var transportMode string
	var transportRetry int
	if cliConf.Transport == "mix" {
		transportMode = "kcp"
	} else {
		transportMode = cliConf.Transport
	}
	for {
		start := time.Now()
		if cliConf.Transport == "mix" {
			transportRetry++
			if transportRetry >= 3 {
				if transportMode == "kcp" {
					transportMode = "tcp"
				} else {
					transportMode = "kcp"
				}
				transportRetry = 0
				log.WithFields(log.Fields{"transport": transportMode}).Infoln("switch to new transport protocol")
			}
		}
		dialAndRun(transportMode)
		if time.Now().Sub(start) > time.Duration(cliConf.Health.TimeOut*int64(time.Second)*3) {
			transportRetry = 0
		}
	}
}
