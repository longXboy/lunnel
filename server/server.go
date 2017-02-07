package main

import (
	"Lunnel/crypto"
	"Lunnel/kcp"
	"Lunnel/msg"
	"Lunnel/vhost"
	"crypto/tls"
	"flag"
	"fmt"
	rawLog "log"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

func main() {
	go serveHttp("0.0.0.0:80")
	go serveHttps("0.0.0.0:443")

	configFile := flag.String("config", "../assets/server/config.json", "path of config file")
	flag.Parse()
	err := LoadConfig(*configFile)
	if err != nil {
		rawLog.Fatalf("load config failed!err:=%v", err)
	}
	InitLog()

	lis, err := kcp.Listen(serverConf.ControlAddr)
	if err != nil {
		panic(err)
	}
	log.WithFields(log.Fields{"address": serverConf.ControlAddr, "protocol": "udp"}).Infoln("server's control listen at")
	for {
		if conn, err := lis.Accept(); err == nil {
			go func() {
				mType, body, err := msg.ReadMsg(conn)
				if err != nil {
					conn.Close()
					log.WithFields(log.Fields{"err": err}).Warningln("read handshake msg failed!")
					return
				}
				if mType == msg.TypeControlClientHello {
					log.WithFields(log.Fields{"encrypt_mode": body.(*msg.ControlClientHello).EncryptMode}).Infoln("new client hello")
					handleControl(conn, body.(*msg.ControlClientHello))
				} else if mType == msg.TypePipeClientHello {
					handlePipe(conn, body.(*msg.PipeClientHello))
				} else {
					log.WithFields(log.Fields{"msgType": mType, "body": body}).Errorln("read handshake msg invalid type!")
				}
			}()
		} else {
			panic(err)
		}
	}
}

func serveHttps(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.WithFields(log.Fields{"addr": addr, "err": err}).Fatalln("listen http failed!")
	}
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("accept http conn failed!")
			continue
		}
		go func() {
			defer conn.Close()
			sconn, info, err := vhost.GetHttpsHostname(conn)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("vhost.GetHttpRequestInfo failed!")
				return
			}
			fmt.Println(info)
			var b []byte = make([]byte, 4096)
			nRead, err := sconn.Read(b)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("sconn.Read failed!")
				return
			}
			fmt.Println(string(b[:nRead]))
		}()
	}
}

func serveHttp(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.WithFields(log.Fields{"addr": addr, "err": err}).Fatalln("listen http failed!")
	}
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("accept http conn failed!")
			continue
		}
		go func() {
			defer conn.Close()
			sconn, info, err := vhost.GetHttpRequestInfo(conn)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("vhost.GetHttpRequestInfo failed!")
				return
			}
			fmt.Println(info)
			var b []byte = make([]byte, 4096)
			nRead, err := sconn.Read(b)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("sconn.Read failed!")
				return
			}
			fmt.Println(string(b[:nRead]))
		}()
	}
}

func handleControl(conn net.Conn, cch *msg.ControlClientHello) {
	var err error
	var ctl *Control
	if cch.EncryptMode == "tls" {
		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(serverConf.TlsCert, serverConf.TlsKey)
		if err != nil {
			conn.Close()
			log.WithFields(log.Fields{"cert": serverConf.TlsCert, "private_key": serverConf.TlsKey, "err": err}).Errorln("client hello,load LoadX509KeyPair failed!")
			return
		}
		tlsConn := tls.Server(conn, tlsConfig)
		ctl = NewControl(tlsConn, cch.EncryptMode)
	} else if cch.EncryptMode == "aes" {
		cryptoConn, err := crypto.NewCryptoConn(conn, []byte(serverConf.SecretKey))
		if err != nil {
			conn.Close()
			log.WithFields(log.Fields{"err": err}).Errorln("client hello,crypto.NewCryptoConn failed!")
			return
		}
		ctl = NewControl(cryptoConn, cch.EncryptMode)
	} else if cch.EncryptMode == "none" {
		ctl = NewControl(conn, cch.EncryptMode)
	} else {
		conn.Close()
		log.WithFields(log.Fields{"encrypt_mode": cch.EncryptMode, "err": "invalid EncryptMode"}).Errorln("client hello failed!")
		return
	}

	err = ctl.ServerHandShake()
	if err != nil {
		conn.Close()
		panic(errors.Wrap(err, "ctl.ServerHandShake"))
	}
	err = ctl.ServerSyncTunnels(serverConf.ServerDomain)
	if err != nil {
		conn.Close()
		panic(errors.Wrap(err, "ctl.ServerSyncTunnels"))
	}
	ctl.Serve()
}

func handlePipe(conn net.Conn, phs *msg.PipeClientHello) {
	err := PipeHandShake(conn, phs)
	if err != nil {
		conn.Close()
		log.WithFields(log.Fields{"err": err}).Warningln("pipe handshake failed!")
	}
}
