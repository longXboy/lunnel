package main

import (
	"Lunnel/control"
	"Lunnel/crypto"
	"Lunnel/kcp"
	"Lunnel/proto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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

	opt := control.Options{Tunnels: make([]proto.Tunnel, 0)}
	opt.Tunnels = append(opt.Tunnels, proto.Tunnel{LocalAddress: "127.0.0.1:32768"})

	ctl := control.NewControl(tlsConn, &opt)
	defer ctl.Close()

	err = ctl.ClientHandShake()
	if err != nil {
		panic(errors.Wrap(err, "control.ClientHandShake"))
	}
	err = ctl.ClientSyncTunnels()
	if err != nil {
		panic(errors.Wrap(err, "ctl.ClientSyncTunnels"))
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
	mux, err := smux.Server(cryptoConn, smuxConfig)
	if err != nil {
		panic(err)
		return
	}
	defer mux.Close()
	idx := 0
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			panic(err)
			return
		}
		idx++
		go func() {
			defer stream.Close()
			fmt.Println("open stream:", idx)
			conn, err := net.Dial("tcp", stream.Tunnel())
			if err != nil {
				panic(err)
			}
			defer conn.Close()
			p1die := make(chan struct{})
			p2die := make(chan struct{})

			go func() {
				io.Copy(stream, conn)
				close(p1die)
				fmt.Println("dst copy done:", idx)
			}()
			go func() {
				io.Copy(conn, stream)
				close(p2die)
				fmt.Println("src copy done:", idx)
			}()
			select {
			case <-p1die:
			case <-p2die:
			}
			fmt.Println("close Stream:", idx)

		}()
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
