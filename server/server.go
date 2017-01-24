package main

import (
	"Lunnel/kcp"
	"crypto/tls"
	"flag"
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

func main() {
	configFile := flag.String("config", "", "a string")
	flag.Parse()
	conf := LoadConfig(*configFile)
	InitLog(conf)
	fmt.Println(conf.TunnelAddr)
	fmt.Println(conf.ControlAddr)

	go func() {
		lis, err := kcp.Listen(conf.TunnelAddr)
		if err != nil {
			panic(err)
		}
		logrus.WithFields(logrus.Fields{"address": conf.TunnelAddr, "protocol": "udp"}).Info("server's tunnel listen at")
		for {
			if conn, err := lis.Accept(); err == nil {
				go handlePipe(conn)
			} else {
				panic(err)
			}
		}
	}()

	lis, err := kcp.Listen(conf.ControlAddr)
	if err != nil {
		panic(err)
	}
	logrus.WithFields(logrus.Fields{"address": conf.ControlAddr, "protocol": "udp"}).Info("server's control listen at")
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
