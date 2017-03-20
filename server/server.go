package main

import (
	"Lunnel/contrib"
	"Lunnel/crypto"
	"Lunnel/kcp"
	"Lunnel/msg"
	"Lunnel/smux"
	"Lunnel/vhost"
	"crypto/tls"
	"flag"
	"fmt"
	rawLog "log"
	"net"

	log "github.com/Sirupsen/logrus"
)

func main() {
	configFile := flag.String("c", "../assets/server/config.yml", "path of config file")
	flag.Parse()
	err := LoadConfig(*configFile)
	if err != nil {
		rawLog.Fatalf("load config failed!err:=%v", err)
	}
	InitLog()
	if serverConf.AuthEnable {
		contrib.InitAuth(serverConf.AuthUrl)
	}
	if serverConf.NotifyEnable {
		contrib.InitNotify(serverConf.NotifyUrl)
	}

	go serveHttp(fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.HttpPort))
	go serveHttps(fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.HttpsPort))
	lis, err := kcp.Listen(fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.ListenPort))
	if err != nil {
		log.WithFields(log.Fields{"address": fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.ListenPort), "protocol": "udp", "err": err}).Fatalln("server's control listen failed!")
	}
	log.WithFields(log.Fields{"address": fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.ListenPort), "protocol": "udp"}).Infoln("server's control listen at")
	for {
		if conn, err := lis.Accept(); err == nil {
			go func() {
				mType, body, err := msg.ReadMsg(conn)
				if err != nil {
					conn.Close()
					log.WithFields(log.Fields{"err": err}).Warningln("read handshake msg failed!")
					return
				}
				if mType == msg.TypeClientHello {
					smuxConfig := smux.DefaultConfig()
					smuxConfig.MaxReceiveBuffer = 4194304
					sess, err := smux.Server(conn, smuxConfig)
					if err != nil {
						conn.Close()
						log.WithFields(log.Fields{"err": err}).Warningln("upgrade to smux.Server failed!")
						return
					}
					stream, err := sess.AcceptStream()
					if err != nil {
						sess.Close()
						log.WithFields(log.Fields{"err": err}).Warningln("accept stream failed!")
						return
					}
					log.WithFields(log.Fields{"encrypt_mode": body.(*msg.ClientHello).EncryptMode}).Infoln("new client hello")
					handleControl(stream, body.(*msg.ClientHello))
					sess.Close()
				} else if mType == msg.TypePipeClientHello {
					handlePipe(conn, body.(*msg.PipeClientHello))
				} else {
					log.WithFields(log.Fields{"msgType": mType, "body": body}).Errorln("read handshake msg invalid type!")
				}
			}()
		} else {
			log.WithFields(log.Fields{"err": err}).Errorln("lis.Accept failed!")
		}
	}
}

func serveHttps(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.WithFields(log.Fields{"addr": addr, "err": err}).Fatalln("listen https failed!")
	}
	log.WithFields(log.Fields{"addr": addr, "err": err}).Println("listen https")
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("accept http conn failed!")
			continue
		}
		go func() {
			sconn, info, err := vhost.GetHttpsHostname(conn)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("vhost.GetHttpRequestInfo failed!")
				return
			}
			fmt.Println(HttpsMap)
			HttpsMapLock.RLock()
			tunnel, isok := HttpsMap[info["Host"]]
			HttpsMapLock.RUnlock()
			tlsConfig, err := newTlsConfig()
			if err != nil {
				log.Errorln("server error cert")
				conn.Close()
				return
			}
			tlcConn := tls.Server(sconn, tlsConfig)
			if isok {
				go proxyConn(tlcConn, tunnel.ctl, tunnel.tunnelName)
			} else {
				conn.Close()
				return
			}
		}()
	}
}

func serveHttp(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.WithFields(log.Fields{"addr": addr, "err": err}).Fatalln("listen http failed!")
	}
	log.WithFields(log.Fields{"addr": addr, "err": err}).Println("listen http")
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Errorln("accept http conn failed!")
			continue
		}
		go func() {
			sconn, info, err := vhost.GetHttpRequestInfo(conn)
			if err != nil {
				conn.Close()
				log.WithFields(log.Fields{"err": err}).Errorln("vhost.GetHttpRequestInfo failed!")
				return
			}
			fmt.Println(HttpMap)
			HttpMapLock.RLock()
			tunnel, isok := HttpMap[info["Host"]]
			HttpMapLock.RUnlock()
			if isok {
				go proxyConn(sconn, tunnel.ctl, tunnel.tunnelName)
			} else {
				conn.Close()
				return
			}
		}()
	}
}

func newTlsConfig() (*tls.Config, error) {
	var err error
	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(serverConf.TlsCert, serverConf.TlsKey)
	if err != nil {
		log.WithFields(log.Fields{"cert": serverConf.TlsCert, "private_key": serverConf.TlsKey, "err": err}).Errorln("load LoadX509KeyPair failed!")
		return tlsConfig, err
	}
	return tlsConfig, nil
}

func handleControl(conn net.Conn, cch *msg.ClientHello) {
	var err error
	var ctl *Control
	if cch.EncryptMode == "tls" {
		tlsConfig, err := newTlsConfig()
		if err != nil {
			conn.Close()
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
		log.WithFields(log.Fields{"err": err, "ClientId": ctl.ClientID}).Errorln("ctl.ServerHandShake failed!")
		return
	}
	err = ctl.ServerSyncTunnels(serverConf.ServerDomain)
	if err != nil {
		conn.Close()
		log.WithFields(log.Fields{"err": err, "ClientId": ctl.ClientID}).Errorln("ctl.ServerSyncTunnels failed!")
		return
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
