package kcp

import (
	"fmt"
	"testing"
	"time"
)

func Test_sockBuf(t *testing.T) {
	SockBuf = 32
	go func() {
		lis, err := Listen("127.0.0.1:8083")
		if err != nil {
			t.Errorf("server listen failed")
		}
		defer lis.Close()
		for {
			fmt.Println("server accept", lis, err)
			conn, err := lis.Accept()
			if err != nil {
				t.Errorf("server accept conn failed")
			}
			var b []byte = make([]byte, 64)
			nread, err := conn.Read(b)
			if err != nil {
				t.Errorf("server read conn failed")
			}
			fmt.Println("server nread:", nread)
			for i := range b {
				b[i] = uint8(i)
			}
			nWrite, err := conn.Write(b)
			fmt.Println("server Write:", nWrite)
			time.Sleep(time.Second * 2)
			conn.Close()
		}
	}()

	conn, err := Dial("127.0.0.1:8083")
	if err != nil {
		t.Errorf("dial server err")
	}
	var body []byte = make([]byte, 64)
	for i := range body {
		body[i] = uint8(255 - i)
	}
	nWrite, err := conn.Write(body)
	if err != nil {
		t.Errorf("client conn write failed!%v", err)
	}
	fmt.Println("client write:", nWrite)
	var b []byte = make([]byte, 64)
	nRead, err := conn.Read(b)
	if err != nil {
		t.Errorf("client conn read failed!%v", err)
	}
	fmt.Println("client read:", nRead)
	conn.Close()
}
