package main

import (
	"Lunnel/control"
	"Lunnel/crypto"
	"Lunnel/kcp"
	"crypto/tls"
	"fmt"
	"io"
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

func (c *compStream) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *compStream) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *compStream) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *compStream) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *compStream) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func newCompStream(conn net.Conn) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func main() {
	go func() {
		addr := "www.longxboy.com:8081"
		fmt.Println("listening:", addr)
		lis, err := kcp.Listen(addr)
		if err != nil {
			panic(err)
		}
		for {
			if conn, err := lis.Accept(); err == nil {
				go handlePipe(conn)
			} else {
				panic(err)
			}
		}
	}()

	addr := "www.longxboy.com:8080"
	fmt.Println("listening:", addr)
	lis, err := kcp.Listen(addr)
	if err != nil {
		panic(err)
	}
	for {
		if conn, err := lis.Accept(); err == nil {
			var err error
			tlsConfig := &tls.Config{}
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			tlsConfig.Certificates[0], err = tls.LoadX509KeyPair("ec.crt", "ec.uncrypted.pem")
			if err != nil {
				panic(err)
				return
			}
			tlsConfig.ServerName = "www.longxboy.com"
			tlsConn := tls.Server(conn, tlsConfig)
			go handleControl(tlsConn)
		} else {
			panic(err)
		}
	}
}

func handleControl(conn net.Conn) {

	ctl := control.NewControl(conn)
	defer ctl.Close()

	err := ctl.ServerHandShake()
	if err != nil {
		panic(errors.Wrap(err, "ctl.ServerHandShake"))
	}

	time.Sleep(time.Second * 3)
}

func handlePipe(conn net.Conn) {
	p := control.NewPipe(conn, nil)
	defer p.Close()
	err := p.ServerHandShake()
	if err != nil {
		panic(err)
	}

	cryptoConn, err := crypto.NewCryptoConn(conn, p.MasterKey)
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

	go func() {
		lis, err := net.Listen("tcp", "0.0.0.0:8080")
		if err != nil {
			panic(err)
		}
		idx := 0
		for {
			conn, err := lis.Accept()
			if err != nil {
				panic(err)
			}
			idx++
			go func() {
				defer conn.Close()
				fmt.Println("open stream:", idx)
				stream, err := sess.OpenStream()
				if err != nil {
					panic(err)
				}
				defer stream.Close()

				p1die := make(chan struct{})
				p2die := make(chan struct{})
				go func() {
					io.Copy(stream, conn)
					close(p1die)
					fmt.Println("src copy done:", idx)
				}()
				go func() {
					io.Copy(conn, stream)
					close(p2die)
					fmt.Println("dst copy done:", idx)
				}()
				select {
				case <-p1die:
				case <-p2die:
				}
				fmt.Println("close Stream:", idx)

			}()

		}
	}()

	/*
		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = 4194304
		mux, err := smux.Server(cryptoConn, smuxConfig)
		if err != nil {
			panic(err)
			return
		}
		defer mux.Close()
		for {
			stream, err := mux.AcceptStream()
			if err != nil {
				panic(err)
				return
			}

			go func() {
				lis, err := net.Listen("tcp", "0.0.0.0:8080")
				if err != nil {
					panic(err)
				}
				for {
					conn, err := lis.Accept()
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
			}()
		}

	*/

	time.Sleep(time.Minute * 60)
}

func getStream() {

}
