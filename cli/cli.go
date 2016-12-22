package main

import (
	lconn "Lunnel/conn"
	"Lunnel/crypto"
	"Lunnel/kcp"
	msg "Lunnel/msg"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/klauspost/compress/snappy"
	"github.com/pkg/errors"
	"github.com/xtaci/smux"
)

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

func main() {
	fmt.Println("open conn")
	conn, err := createConn(true)
	if err != nil {
		panic(err)
	}
	stream, err := conn.OpenStream()
	if err != nil {
		panic(err)
	}
	tlsConfig, err := LoadTLSConfig([]string{"./ec.crt"})
	if err != nil {
		panic(err)
	}
	tlsConfig.ServerName = "www.longxboy.com"
	tlsConn := tls.Client(stream, tlsConfig)

	priv, keyMsg := crypto.GenerateKeyExChange()
	if keyMsg == nil || priv == nil {
		panic(fmt.Errorf("error exchange key is nil"))
	}
	controlConn := lconn.NewControlConn(tlsConn)
	ckem := msg.KeyExchangeMsg{CipherText: keyMsg}
	message, err := json.Marshal(ckem)
	if err != nil {
		panic(errors.Wrap(err, "marshal KeyExchangeMsg"))
	}
	err = controlConn.Write(msg.TypeClientKeyExchange, message)
	if err != nil {
		panic(err)
	}
	mType, body, err := controlConn.Read()
	if mType == msg.TypeServerKeyExchange {
		var skem msg.KeyExchangeMsg
		err = json.Unmarshal(body, &skem)
		if err != nil {
			panic(errors.Wrap(err, "unmarshal KeyExchangeMsg"))
		}
		preMasterSecret, err := crypto.ProcessKeyExchange(priv, skem.CipherText)
		if err != nil {
			panic(errors.Wrap(err, "crypto.ProcessKeyExchange"))
		}
		fmt.Println(preMasterSecret)
	}
	controlConn.Close()
	conn.Close()
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

func createConn(noComp bool) (*smux.Session, error) {

	kcpconn, err := kcp.Dial("www.longxboy.com:8080")
	if err != nil {
		return nil, errors.Wrap(err, "kcp dial")
	}
	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = kcp.SockBuf
	var session *smux.Session
	if noComp {
		session, err = smux.Client(kcpconn, smuxConfig)
	} else {
		session, err = smux.Client(newCompStream(kcpconn), smuxConfig)
	}
	if err != nil {
		return nil, errors.Wrap(err, "smux wrap conn failed")
	}
	return session, nil
}
