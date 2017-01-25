package main

import (
	"Lunnel/kcp"
	"crypto/tls"
	"flag"
	"log"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

func main() {
	configFile := flag.String("config", "", "path of config file")
	flag.Parse()
	err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("load config failed!err:=%v", err)
	}
	InitLog()

	go func() {
		lis, err := kcp.Listen(serverConf.TunnelAddr)
		if err != nil {
			panic(err)
		}
		logrus.WithFields(logrus.Fields{"address": serverConf.TunnelAddr, "protocol": "udp"}).Info("server's tunnel listen at")
		for {
			if conn, err := lis.Accept(); err == nil {
				go handlePipe(conn)
			} else {
				panic(err)
			}
		}
	}()

	lis, err := kcp.Listen(serverConf.ControlAddr)
	if err != nil {
		panic(err)
	}
	logrus.WithFields(logrus.Fields{"address": serverConf.ControlAddr, "protocol": "udp"}).Info("server's control listen at")
	for {
		if conn, err := lis.Accept(); err == nil {
			var err error
			tlsConfig := &tls.Config{}
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(serverConf.TlsCert, serverConf.TlsKey)
			if err != nil {
				panic(serverConf.TlsCert + serverConf.TlsKey + err.Error())
				return
			}
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
	err = ctl.ServerSyncTunnels(serverConf.ServerDomain)
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
