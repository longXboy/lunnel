package transport

import (
	"fmt"
	"testing"
	"time"

	"github.com/longXboy/lunnel/util"
)

func Test_Quic(t *testing.T) {
	tlsConfig := util.GenerateTLSConfig()
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
