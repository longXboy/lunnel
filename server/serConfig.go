package main

import (
	"crypto/sha1"
	"encoding/json"
	"io/ioutil"
	rawLog "log"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

type Config struct {
	Prod         bool
	LogFile      string
	ListenPort   int
	ListenIP     string
	HttpPort     uint16
	HttpsPort    uint16
	ServerDomain string
	TlsCert      string
	TlsKey       string
	SecretKey    string
	//none:means no encrypt
	//aes:means exchange premaster key in aes mode
	//tls:means exchange premaster key in tls mode
	//default value is tls
	EncryptMode  string
	AuthEnable   bool
	AuthUrl      string
	NotifyEnable bool
	NotifyUrl    string
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
	if serverConf.ListenIP == "" {
		serverConf.ListenIP = "0.0.0.0"
	}
	if serverConf.ListenPort == 0 {
		serverConf.ListenPort = 8080
	}
	if serverConf.HttpPort == 0 {
		serverConf.HttpPort = 80
	}
	if serverConf.HttpsPort == 0 {
		serverConf.HttpsPort = 443
	}
	if serverConf.ServerDomain == "" {
		serverConf.ServerDomain = "lunnel.snakeoil.com"
	}
	if serverConf.EncryptMode == "" {
		serverConf.EncryptMode = "tls"
	}
	if serverConf.EncryptMode != "tls" && serverConf.EncryptMode != "aes" && serverConf.EncryptMode != "none" {
		return errors.Errorf("invalid encrypt mode:%s", serverConf.EncryptMode)
	}
	if serverConf.TlsCert == "" {
		serverConf.TlsCert = "../assets/server/snakeoil.crt"
	}
	if serverConf.TlsKey == "" {
		serverConf.TlsKey = "../assets/server/snakeoil.key"
	}
	if serverConf.EncryptMode == "aes" {
		if serverConf.SecretKey == "" {
			serverConf.SecretKey = "defaultpassword"
		}
		pass := pbkdf2.Key([]byte(serverConf.SecretKey), []byte("lunnel"), 4096, 32, sha1.New)
		serverConf.SecretKey = string(pass[:16])
	}
	return nil
}

func InitLog() {
	if serverConf.Prod {
		log.SetLevel(log.WarnLevel)
	} else {
		log.SetLevel(log.DebugLevel)
	}
	if serverConf.LogFile != "" {
		f, err := os.OpenFile(serverConf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
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
