package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	rawLog "log"
	"time"

	"github.com/getsentry/raven-go"
	"github.com/longXboy/Lunnel/crypto"
	"github.com/longXboy/Lunnel/log"
	"github.com/longXboy/Lunnel/msg"
	"github.com/longXboy/Lunnel/transport"
	"github.com/longXboy/Lunnel/util"
	"github.com/longXboy/smux"
)

const reconnectInterval = 10

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

func dialAndRun(transportMode string) {
	defer time.Sleep(time.Duration(time.Second * reconnectInterval))
	log.WithFields(log.Fields{"addr": cliConf.ServerAddr, "transportMode": transportMode}).Infoln("trying to create control conn to server")
	conn, err := transport.CreateConn(cliConf.ServerAddr, transportMode, cliConf.HttpProxy)
	if err != nil {
		log.WithFields(log.Fields{"server address": cliConf.ServerAddr, "err": err}).Warnln("create ControlAddr conn failed!")
		return
	}
	defer conn.Close()
	chello := msg.ClientHello{EncryptMode: cliConf.EncryptMode, EnableCompress: cliConf.EnableCompress}
	err = msg.WriteMsg(conn, msg.TypeClientHello, chello)
	if err != nil {
		log.WithFields(log.Fields{"server address": cliConf.ServerAddr, "err": err}).Warnln("write ControlClientHello failed!")
		return
	}
	mType, body, err := msg.ReadMsg(conn)
	if err != nil {
		log.WithFields(log.Fields{"server address": cliConf.ServerAddr, "err": err}).Warnln("read server hello failed!")
		return
	}
	if mType == msg.TypeError {
		serverError := body.(*msg.Error)
		log.WithFields(log.Fields{"server error": serverError.Error()}).Warnln("client hello failed!")
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
	tunnels := make(map[string]msg.Tunnel, 0)
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
		tunnel.Local.Port = uint16(localPort)
		tunnel.Public.Schema = tc.Schema
		tunnel.Public.Host = tc.Host
		tunnel.Public.Port = tc.Port
		if tunnel.Public.Host == "" && tunnel.Public.Port == 0 {
			tunnel.Public.AllowReallocate = true
		}
		tunnels[name] = tunnel
	}
	ctl := NewControl(stream, cliConf.EncryptMode, transportMode, tunnels)
	err = ctl.ClientHandShake()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("control.ClientHandShake failed!")
		return
	}
	log.WithFields(log.Fields{"client_id": ctl.ClientID.Hex()}).Infoln("server handshake success!")
	err = ctl.ClientAddTunnels()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("control.ClientSyncTunnels failed!")
		return
	}
	ctl.Run()
}

func Main() {
	configFile := flag.String("c", "./config.yml", "path of config file")
	flag.Parse()
	err := LoadConfig(*configFile)
	if err != nil {
		rawLog.Fatalf("load config failed!err:=%v", err)
	}
	log.Init(cliConf.Debug, cliConf.LogFile)

	raven.SetDSN(cliConf.DSN)

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
		if time.Now().Sub(start) > time.Duration(pingTimeout*3) {
			transportRetry = 0
		}
	}
}
