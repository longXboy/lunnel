package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	rawLog "log"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/klauspost/compress/snappy"
	"github.com/longXboy/Lunnel/crypto"
	"github.com/longXboy/Lunnel/msg"
	"github.com/longXboy/Lunnel/transport"
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
	var chello msg.ClientHello
	chello.EncryptMode = cliConf.EncryptMode
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
		log.Infoln("recv msg serer hello success")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	sess, err := smux.Client(conn, smuxConfig)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("upgrade to smux.Client failed!")
		return
	}
	defer sess.Close()
	stream, err := sess.OpenStream("")
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Warnln("sess.OpenStream failed!")
		return
	}
	var ctl *Control
	if cliConf.EncryptMode == "tls" {
		tlsConfig, err := LoadTLSConfig([]string{cliConf.Tls.TrustedCert})
		if err != nil {
			log.WithFields(log.Fields{"trusted cert": cliConf.Tls.TrustedCert, "err": err}).Fatalln("load tls trusted cert failed!")
			return
		}
		tlsConfig.ServerName = cliConf.Tls.ServerName
		tlsConn := tls.Client(stream, tlsConfig)
		ctl = NewControl(tlsConn, cliConf.EncryptMode, transportMode)
	} else if cliConf.EncryptMode == "aes" {
		cryptoConn, err := crypto.NewCryptoConn(stream, []byte(cliConf.Aes.SecretKey))
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("client hello,crypto.NewCryptoConn failed!")
			return
		}
		ctl = NewControl(cryptoConn, cliConf.EncryptMode, transportMode)
	} else if cliConf.EncryptMode == "none" {
		ctl = NewControl(stream, cliConf.EncryptMode, transportMode)
	} else {
		log.WithFields(log.Fields{"encrypt_mode": cliConf.EncryptMode, "err": "invalid EncryptMode"}).Errorln("client hello failed!")
		return
	}
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

func main() {
	configFile := flag.String("c", "../assets/client/config.yml", "path of config file")
	flag.Parse()
	err := LoadConfig(*configFile)
	if err != nil {
		rawLog.Fatalf("load config failed!err:=%v", err)
	}
	InitLog()

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

type compStream struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func newCompStream(conn net.Conn) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}
func (c *compStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *compStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	return n, err
}

func (c *compStream) Close() error {
	return c.conn.Close()
}
