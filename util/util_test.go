package util

import (
	"testing"
)

func Test_ParseAddr(t *testing.T) {
	schema, host, port, err := ParseLocalAddr("http://127.0.0.1")
	if err != nil || schema != "http" || host != "127.0.0.1" || port != "" {
		t.Error(err, "http://127.0.0.1", schema, host, port)
	}
	schema, host, port, err = ParseLocalAddr("127.0.0.1")
	if err != nil || schema != "" || host != "127.0.0.1" || port != "" {
		t.Error(err, "127.0.0.1", schema, host, port)
	}
	schema, host, port, err = ParseLocalAddr("127.0.0.1:80")
	if err != nil || schema != "" || host != "127.0.0.1" || port != "80" {
		t.Error(err, "127.0.0.1:80", schema, host, port)
	}
	schema, host, port, err = ParseLocalAddr("http://127.0.0.1:445")
	if err != nil || schema != "http" || host != "127.0.0.1" || port != "445" {
		t.Error(err, "127.0.0.1:80", schema, host, port)
	}
	schema, host, port, err = ParseLocalAddr("unix:///var/run/docker.sock")
	if err != nil || schema != "unix" || host != "/var/run/docker.sock" || port != "" {
		t.Error(err, "127.0.0.1:80", schema, host, port)
	}
}
