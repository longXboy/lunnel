package main

import (
	"Lunnel/kcp"
	"Lunnel/msg"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/klauspost/compress/snappy"
	"github.com/pkg/errors"
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

func CreateConn(addr string, noComp bool) (net.Conn, error) {
	fmt.Println("open conn:", addr)
	kcpconn, err := kcp.Dial(addr)
	if err != nil {
		return nil, errors.Wrap(err, "kcp dial")
	}
	return kcpconn, nil
}

func main() {
	conn, err := CreateConn("www.longxboy.com:8080", true)
	if err != nil {
		panic(err)
	}

	tlsConfig, err := LoadTLSConfig([]string{"./ec.crt"})
	if err != nil {
		panic(err)
	}
	tlsConfig.ServerName = "www.longxboy.com"
	tlsConn := tls.Client(conn, tlsConfig)

	opt := Options{Tunnels: make([]msg.Tunnel, 0)}
	opt.Tunnels = append(opt.Tunnels, msg.Tunnel{LocalAddress: "127.0.0.1:32768"})

	ctl := NewControl(tlsConn, &opt)
	defer ctl.Close()

	err = ctl.ClientHandShake()
	if err != nil {
		panic(errors.Wrap(err, "control.ClientHandShake"))
	}
	err = ctl.ClientSyncTunnels()
	if err != nil {
		panic(errors.Wrap(err, "ctl.ClientSyncTunnels"))
	}
	ctl.Run()

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
