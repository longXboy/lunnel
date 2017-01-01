package main

import (
	"Lunnel/control"
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
	/*stream, err := conn.OpenStream()
	if err != nil {
		panic(err)
	}*/
	tlsConfig, err := LoadTLSConfig([]string{"./ec.crt"})
	if err != nil {
		panic(err)
	}
	tlsConfig.ServerName = "www.longxboy.com"
	tlsConn := tls.Client(conn, tlsConfig)

	priv, keyMsg := crypto.GenerateKeyExChange()
	if keyMsg == nil || priv == nil {
		panic(fmt.Errorf("error exchange key is nil"))
	}
	//这里应该将tlsconn封装在controller中，这样升级之后可以立刻defer close
	ctl := control.NewControlConn(tlsConn)
	defer ctl.Close()

	ckem := msg.KeyExchangeMsg{CipherText: keyMsg}
	message, err := json.Marshal(ckem)
	if err != nil {
		panic(errors.Wrap(err, "marshal KeyExchangeMsg"))
	}
	err = ctl.Write(msg.TypeClientKeyExchange, message)
	if err != nil {
		panic(err)
	}
	mType, body, err := ctl.Read()
	if err != nil {
		panic(err)
	}
	var preMasterSecret []byte
	if mType == msg.TypeServerKeyExchange {
		var skem msg.KeyExchangeMsg
		err = json.Unmarshal(body, &skem)
		if err != nil {
			panic(errors.Wrap(err, "unmarshal KeyExchangeMsg"))
		}
		preMasterSecret, err = crypto.ProcessKeyExchange(priv, skem.CipherText)
		if err != nil {
			panic(errors.Wrap(err, "crypto.ProcessKeyExchange"))
		}
		fmt.Println(preMasterSecret)
		ctl.PreMasterSecret = preMasterSecret
	} else {
		panic(fmt.Errorf("invalid msg type expect:%v recv:%v", msg.TypeServerKeyExchange, mType))
	}
	mType, body, err = ctl.Read()
	if err != nil {
		panic(err)
	}

	if mType == msg.TypeClientIdGenerate {
		var cidm msg.ClientIdGenerate
		err = json.Unmarshal(body, &cidm)
		if err != nil {
			panic(errors.Wrap(err, "unmarshal ClientIdGenerate"))
		}
		ctl.ClientID = cidm.ClientID
		fmt.Println("client_id:", ctl.ClientID)
	} else {
		panic(fmt.Errorf("invalid msg type expect:%v recv:%v", msg.TypeClientIdGenerate, mType))
	}

	pipeConn, err := createConn("www.longxboy.com:8081", true)
	if err != nil {
		panic(err)
	}
	pipe := control.NewPipe(pipeConn)
	defer pipe.Close()
	uuid := pipe.GenerateUUID()
	var uuidm msg.PipeHandShake
	uuidm.PipeID = uuid
	uuidm.ClientID = ctl.ClientID
	message, err = json.Marshal(uuidm)
	if err != nil {
		panic(errors.Wrap(err, "unmarshal PipeUUIdGenerate"))
	}
	err = pipe.Write(msg.TypePipeHandShake, message)
	if err != nil {
		panic(err)
	}
	prf := crypto.NewPrf12()
	var masterKey []byte = make([]byte, 16)
	uuidmar := make([]byte, 16)
	for i := range uuidm.PipeID {
		uuidmar[i] = uuidm.PipeID[i]
	}
	fmt.Println("uuid:", uuidmar)

	prf(masterKey, preMasterSecret, []byte(fmt.Sprintf("%d", ctl.ClientID)), uuidmar)
	fmt.Println("masterKey:", masterKey)

	cryptoConn, err := crypto.NewCryptoConn(pipeConn, masterKey)
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

	_, err = stream.Write([]byte("hehehenidaye"))
	if err != nil {
		panic(err)
	}
	var buf []byte = make([]byte, 64)
	_, err = stream.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(buf))
	buf = make([]byte, 64)
	_, err = stream.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(buf))
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
	// stream multiplex
	/*smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = kcp.SockBuf
	var session *smux.Session
	if noComp {
		session, err = smux.Client(kcpconn, smuxConfig)
	} else {
		session, err = smux.Client(newCompStream(kcpconn), smuxConfig)
	}
	if err != nil {
		return nil, errors.Wrap(err, "smux wrap conn failed")
	}*/
	return kcpconn, nil
}
