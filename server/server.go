package main

import (
	"Lunnel/kcp"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pkg/errors"
)

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

	ctl := NewControl(conn)
	defer ctl.Close()

	err := ctl.ServerHandShake()
	if err != nil {
		panic(errors.Wrap(err, "ctl.ServerHandShake"))
	}
	err = ctl.ServerSyncTunnels("www.longxboy.com")
	if err != nil {
		panic(errors.Wrap(err, "ctl.ServerSyncTunnels"))
	}
	ctl.Serve()
}

func handlePipe(conn net.Conn) {
	err := PipeHandShake(conn)
	if err != nil {
		conn.Close()
		panic(err)
	}
}
