package main

import (
	"Lunnel/crypto"
	"Lunnel/kcp"
	"Lunnel/msg"
	"Lunnel/smux"
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
	"github.com/pkg/errors"
)

var reconnectInterval int64 = 3

func LoadTLSConfig(rootCertPaths []string) (*tls.Config, error) {
	pool := x509.NewCertPool()

	for _, certPath := range rootCertPaths {
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

func CreateConn(addr string, noComp bool) (net.Conn, error) {
	kcpconn, err := kcp.Dial(addr)
	if err != nil {
		return nil, errors.Wrap(err, "kcp dial")
	}
	return kcpconn, nil
}

func main() {
	configFile := flag.String("c", "../assets/client/config.yml", "path of config file")
	flag.Parse()
	err := LoadConfig(*configFile)
	if err != nil {
		rawLog.Fatalf("load config failed!err:=%v", err)
	}
	InitLog()

	for {
		log.WithFields(log.Fields{"addr": cliConf.ServerAddr}).Infoln("trying to create control conn to server")
		conn, err := CreateConn(cliConf.ServerAddr, true)
		if err != nil {
			log.WithFields(log.Fields{"server address": cliConf.ServerAddr, "err": err}).Warnln("create ControlAddr conn failed!")
			time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
			continue
		}

		var chello msg.ClientHello
		chello.EncryptMode = cliConf.EncryptMode
		fmt.Println("write msg client hello")
		err = msg.WriteMsg(conn, msg.TypeClientHello, chello)
		if err != nil {
			conn.Close()
			log.WithFields(log.Fields{"server address": cliConf.ServerAddr, "err": err}).Warnln("write ControlClientHello failed!")
			time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
			continue
		}
		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = 4194304
		sess, err := smux.Client(conn, smuxConfig)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Warnln("upgrade to smux.Client failed!")
			time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
			continue
		}
		stream, err := sess.OpenStream("")
		if err != nil {
			sess.Close()
			log.WithFields(log.Fields{"err": err}).Warnln("sess.OpenStream failed!")
			time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
			continue
		}
		var ctl *Control
		if cliConf.EncryptMode == "tls" {
			tlsConfig, err := LoadTLSConfig([]string{cliConf.TrustedCert})
			if err != nil {
				sess.Close()
				log.WithFields(log.Fields{"trusted cert": cliConf.TrustedCert, "err": err}).Fatalln("load tls trusted cert failed!")
				time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
				continue
			}
			tlsConfig.ServerName = cliConf.ServerName
			tlsConn := tls.Client(stream, tlsConfig)
			ctl = NewControl(tlsConn, cliConf.EncryptMode)
		} else if cliConf.EncryptMode == "aes" {
			cryptoConn, err := crypto.NewCryptoConn(stream, []byte(cliConf.SecretKey))
			if err != nil {
				sess.Close()
				log.WithFields(log.Fields{"err": err}).Errorln("client hello,crypto.NewCryptoConn failed!")
				time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
				continue
			}
			ctl = NewControl(cryptoConn, cliConf.EncryptMode)
		} else if cliConf.EncryptMode == "none" {
			ctl = NewControl(stream, cliConf.EncryptMode)
		} else {
			sess.Close()
			log.WithFields(log.Fields{"encrypt_mode": cliConf.EncryptMode, "err": "invalid EncryptMode"}).Errorln("client hello failed!")
			time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
			continue
		}
		err = ctl.ClientHandShake()
		if err != nil {
			sess.Close()
			log.WithFields(log.Fields{"err": err}).Warnln("control.ClientHandShake failed!")
			time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
			continue
		}
		fmt.Println("client handshake end")
		err = ctl.ClientSyncTunnels()
		if err != nil {
			sess.Close()
			log.WithFields(log.Fields{"err": err}).Warnln("control.ClientSyncTunnels failed!")
			time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
			continue
		}
		ctl.Run()
		sess.Close()
		time.Sleep(time.Duration(int64(time.Second) * reconnectInterval))
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
