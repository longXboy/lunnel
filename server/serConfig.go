package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

type Config struct {
	Prod         bool
	LogFile      string
	ControlAddr  string
	TunnelAddr   string
	ServerDomain string
	TlsCert      string
	TlsKey       string
	SecretKey    string
	//none:means no encrypt
	//aes:means exchange premaster key in aes mode
	//tls:means exchange premaster key in tls mode
	//default value is tls
	EncryptMode string
}

var serverConf Config

func LoadConfig(configFile string) error {
	if configFile != "" {
		content, err := ioutil.ReadFile(configFile)
		if err != nil {
			return errors.Wrap(err, "read config file")
		}
		err = json.Unmarshal(content, &serverConf)
		if err != nil {
			return errors.Wrap(err, "unmarshal config file")
		}
	}
	if serverConf.ControlAddr == "" {
		serverConf.ControlAddr = "0.0.0.0:8080"
	}
	if serverConf.TunnelAddr == "" {
		serverConf.TunnelAddr = "0.0.0.0:8081"
	}
	if serverConf.ServerDomain == "" {
		serverConf.ServerDomain = "lunnel.snakeoil.com"
	}
	if serverConf.EncryptMode == "" {
		serverConf.EncryptMode = "tls"
	}
	if serverConf.EncryptMode == "tls" {
		if serverConf.TlsCert == "" {
			serverConf.TlsCert = "../assets/server/snakeoil.crt"
		}
		if serverConf.TlsKey == "" {
			serverConf.TlsKey = "../assets/server/snakeoil.key"
		}
	} else if serverConf.EncryptMode == "aes" {
		if serverConf.SecretKey == "" {
			serverConf.SecretKey = "defaultpassword"
		}
	} else if serverConf.EncryptMode != "none" {
		return errors.Errorf("load config failed!err:=unsupported enrypt mode(%s)", serverConf.EncryptMode)
	}
	return nil
}

func InitLog() {
	if serverConf.Prod {
		logrus.SetLevel(logrus.WarnLevel)
	} else {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if serverConf.LogFile != "" {
		f, err := os.OpenFile(serverConf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			log.Fatalf("open log file failed!err:=%v\n", err)
			return
		}
		logrus.SetOutput(f)
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetOutput(os.Stdout)
		logrus.SetFormatter(&logrus.TextFormatter{})
	}
}
