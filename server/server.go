package main

import (
	lconn "Lunnel/conn"
	"Lunnel/crypto"
	"Lunnel/kcp"
	"Lunnel/msg"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/klauspost/compress/snappy"
	"github.com/pkg/errors"
	"github.com/xtaci/smux"
)

const (
	noDelay        = 0
	interval       = 40
	resend         = 0
	noCongestion   = 0
	sockBuf        = 4194304
	noComp         = true
	dataShard      = 10
	parityShard    = 3
	udpSegmentSize = 1472
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
)

type compStream struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
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

func newCompStream(conn net.Conn) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func main() {
	fmt.Println("listening")
	lis, err := kcp.Listen("www.longxboy.com:8080")
	if err != nil {
		panic(err)
	}
	for {
		if conn, err := lis.Accept(); err == nil {
			if noComp {
				go handleMux(conn)
			} else {
				go handleMux(newCompStream(conn))
			}
		} else {
			panic(err)
		}
	}
}

func handleMux(conn io.ReadWriteCloser) {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = sockBuf
	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer mux.Close()
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			log.Println("accpect failed!", err)
			return
		}
		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair("ec.crt", "ec.uncrypted.pem")
		if err != nil {
			panic(err)
			return
		}
		tlsConfig.ServerName = "www.longxboy.com"
		tlsConn := tls.Server(stream, tlsConfig)

		controlConn := lconn.NewControlConn(tlsConn)
		mType, body, err := controlConn.Read()
		if mType == msg.TypeClientKeyExchange {
			var ckem msg.KeyExchangeMsg
			err = json.Unmarshal(body, &ckem)
			if err != nil {
				panic(errors.Wrap(err, "unmarshal KeyExchangeMsg"))
			}
			priv, keyMsg := crypto.GenerateKeyExChange()
			if keyMsg == nil || priv == nil {
				panic(fmt.Errorf("error exchange key is nil"))
			}
			preMasterSecret, err := crypto.ProcessKeyExchange(priv, ckem.CipherText)
			if err != nil {
				panic(errors.Wrap(err, "crypto.ProcessKeyExchange"))
			}
			fmt.Println(preMasterSecret)
			skem := msg.KeyExchangeMsg{CipherText: keyMsg}
			message, err := json.Marshal(skem)
			if err != nil {
				panic(errors.Wrap(err, "marshal KeyExchangeMsg"))
			}
			err = controlConn.Write(msg.TypeServerKeyExchange, message)
			if err != nil {
				panic(err)
			}
		}
		time.Sleep(time.Second)
		tlsConn.Close()
	}
}
