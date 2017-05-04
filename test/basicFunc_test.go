package test

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/longXboy/lunnel/client"
	"github.com/longXboy/lunnel/server"
)

func Test_BaiscFunc(t *testing.T) {
	serverConfig := `server_domain: example.com
port: 8080
aes:
  secret_key: password
tls:
  cert: ./example.crt
  key: ./example.key
http_port: 8880
https_port: 4443`

	cliConfig := `server_addr: 127.0.0.1:8080
tunnels:
  echo:
    schema: tcp
    port: 10881
    local: tcp://127.0.0.1:10880
tls:
  trusted_cert: ./example.crt
  server_name: example.com
enable_compress: true`

	go server.Main([]byte(serverConfig), "yaml")
	time.Sleep(time.Millisecond * 50)
	go client.Main([]byte(cliConfig), "yaml")

	go startEchoServer(t)
	time.Sleep(time.Millisecond * 100)
	fmt.Println("starting dail to 127.0.0.1:10881")
	conn, err := net.Dial("tcp", "127.0.0.1:10881")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second * 3))
	testStr := "xixixixixixi\n"
	_, err = conn.Write([]byte(testStr))
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	buff, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if string(buff) != testStr {
		t.Errorf("bytes returned(%v) not match %v!", buff, []byte(testStr))
		return
	}
	testBytes := []byte{}
	for i := 0; i < 99999; i++ {
		testBytes = append(testBytes, 22)
	}
	testBytes = append(testBytes, '\n')

	_, err = conn.Write(testBytes)
	if err != nil {
		t.Fatal(err)
	}
	buff, err = reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if string(buff) != string(testBytes) {
		t.Errorf("bytes returned(%v) not match %v!", buff, []byte(testStr))
		return
	}
}

func startEchoServer(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:10880")
	if err != nil {
		t.Error(err)
		fmt.Printf("echo server listen error: %v\n", err)
		return
	}
	fmt.Println("serve on 0.0.0.0:10880")
	for {
		c, err := l.Accept()
		if err != nil {
			t.Error(err)
			fmt.Printf("echo server accept error: %v\n", err)
			return
		}

		go echoWorker(t, c)
	}
}

func echoWorker(t *testing.T, c net.Conn) {
	defer c.Close()
	reader := bufio.NewReader(c)
	for {
		buff, err := reader.ReadBytes('\n')
		if err != nil {
			t.Error(err)
			return
		}
		nWrite, err := c.Write(buff)
		if err != nil {
			t.Error(err)
			return
		}
		if nWrite != len(buff) {
			t.Errorf("nWrite(%d) !=  len(buff) (%d)", nWrite, len(buff))
			return
		}
	}
}
