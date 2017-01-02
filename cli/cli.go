package main

import (
	"Lunnel/control"
	"Lunnel/crypto"
	"Lunnel/kcp"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

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
	conn, err := createConn("www.longxboy.com:8080", true)
	if err != nil {
		panic(err)
	}

	tlsConfig, err := LoadTLSConfig([]string{"./ec.crt"})
	if err != nil {
		panic(err)
	}
	tlsConfig.ServerName = "www.longxboy.com"
	tlsConn := tls.Client(conn, tlsConfig)

	ctl := control.NewControl(tlsConn)
	defer ctl.Close()

	err = ctl.ClientHandShake()
	if err != nil {
		panic(errors.Wrap(err, "control.ClientHandShake"))
	}

	pipeConn, err := createConn("www.longxboy.com:8081", true)
	if err != nil {
		panic(err)
	}
	pipe := control.NewPipe(pipeConn, ctl)
	defer pipe.Close()
	pipe.ClientHandShake()

	cryptoConn, err := crypto.NewCryptoConn(pipeConn, pipe.MasterKey)
	if err != nil {
		panic(err)
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	sess, err := smux.Client(cryptoConn, smuxConfig)
	if err != nil {
		panic(err)
	}
	defer sess.Close()
	stream, err := sess.OpenStream()
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	for {
		conn, err := net.Dial("tcp", "127.0.0.1:32768")
		if err != nil {
			panic(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(stream, conn)
		}()
		go func() {
			defer wg.Done()
			io.Copy(conn, stream)
		}()
		wg.Wait()
	}

	time.Sleep(time.Second * 3)
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

func createConn(addr string, noComp bool) (net.Conn, error) {
	fmt.Println("open conn:", addr)
	kcpconn, err := kcp.Dial(addr)
	if err != nil {
		return nil, errors.Wrap(err, "kcp dial")
	}
	return kcpconn, nil
}
