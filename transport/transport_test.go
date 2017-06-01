package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func Test_Quic(t *testing.T) {
	tlsConfig := generateTLSConfig()
	go func() {
		lis, err := ListenQuic(":8080", tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		for {
			sess, err := lis.Accept()
			if err != nil {
				t.Fatal(err)
			}
			stream, err := sess.AcceptStream()
			if err != nil {
				t.Fatal(err)
			}
			var p []byte = make([]byte, 1024)
			nRead, err := stream.Read(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(p[:nRead]) != "client hello" {
				t.Errorf("server read error")
			}
			_, err = stream.Write([]byte("server hello"))
			if err != nil {
				t.Fatal(err)
			}

			stream2, err := sess.OpenStream()
			_, err = stream2.Write([]byte("tunnelname"))
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Millisecond)
			stream2.Close()
		}

	}()
	tlsConfig.InsecureSkipVerify = true
	sess, err := CreateQuicSess("127.0.0.1:8080", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Write([]byte("client hello"))
	if err != nil {
		t.Fatal(err)
	}
	var p []byte = make([]byte, 1024)
	nRead, err := stream.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(p[:nRead]) != "server hello" {
		t.Errorf("client read error")
	}
	for {
		streamTemp, err := sess.AcceptStream()
		if err != nil {
			t.Fatal(err)
		}
		defer streamTemp.Close()
		var temp []byte = make([]byte, 1024)
		nRead, err = streamTemp.Read(temp)
		if err != nil {
			t.Fatal(err)
		}
		if string(temp[:nRead]) != "tunnelname" {
			t.Errorf("client accept stream and read tunnelname failed!\n")
			return
		}
		fmt.Println(string(temp[:nRead]))
		break
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
