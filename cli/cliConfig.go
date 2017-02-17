package main

import (
	"Lunnel/msg"
	"crypto/sha1"
	"encoding/json"
	"io/ioutil"
	rawLog "log"
	"net"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

type Config struct {
	Prod    bool
	LogFile string
	//if EncryptMode is tls and ServerName is empty,ServerAddr can't be IP format
	ServerAddr  string `yaml:"server_addr"`
	ServerName  string
	TrustedCert string
	SecretKey   string
	//none:means no encrypt
	//aes:means exchange premaster key in aes mode
	//tls:means exchange premaster key in tls mode
	//default value is tls
	EncryptMode       string
	Tunnels           []msg.Tunnel `yaml:"tunnels"`
	ReconnectInterval int64
}

var cliConf Config

func LoadConfig(configFile string) error {
	if configFile != "" {
		content, err := ioutil.ReadFile(configFile)
		if err != nil {
			return errors.Wrap(err, "read config file")
		}
		err = json.Unmarshal(content, &cliConf)
		if err != nil {
			return errors.Wrap(err, "unmarshal config file")
		}
	}
	if cliConf.ServerAddr == "" {
		cliConf.ServerAddr = "lunnel.snakeoil.com:8080"
	}
	if cliConf.EncryptMode == "" {
		cliConf.EncryptMode = "tls"
	}
	if cliConf.EncryptMode == "aes" {
		if cliConf.SecretKey == "" {
			cliConf.SecretKey = "defaultpassword"
		}
		pass := pbkdf2.Key([]byte(cliConf.SecretKey), []byte("lunnel"), 4096, 32, sha1.New)
		cliConf.SecretKey = string(pass[:16])
	}
	if cliConf.EncryptMode != "tls" && cliConf.EncryptMode != "aes" && cliConf.EncryptMode != "none" {
		return errors.New("invalid EncryptMode")
	}
	if cliConf.EncryptMode == "tls" && cliConf.ServerName == "" {
		var err error
		cliConf.ServerName, err = resovleServerName(cliConf.ServerAddr)
		if err != nil {
			return errors.Wrap(err, "resovleServerName")
		}
	}
	if cliConf.ReconnectInterval == 0 {
		cliConf.ReconnectInterval = 3
	}
	if cliConf.Tunnels == nil || len(cliConf.Tunnels) == 0 {
		return errors.New("you must specify at least one tunnel")
	}
	return nil
}

func resovleServerName(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", errors.Wrap(err, "net.SplitHostPort")
	}
	if net.ParseIP(host) != nil {
		return "", errors.New("ServerAddress can't be ip format")
	}
	return host, nil
}

func InitLog() {
	if cliConf.Prod {
		log.SetLevel(log.WarnLevel)
	} else {
		log.SetLevel(log.DebugLevel)
	}
	if cliConf.LogFile != "" {
		f, err := os.OpenFile(cliConf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			rawLog.Fatalf("open log file failed!err:=%v\n", err)
			return
		}
		log.SetOutput(f)
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetOutput(os.Stdout)
		log.SetFormatter(&log.TextFormatter{})
	}
}
