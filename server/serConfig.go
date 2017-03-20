package main

import (
	"crypto/sha1"
	"encoding/json"
	"io/ioutil"
	rawLog "log"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Prod         bool   `yaml:"prod,omitempty"`
	LogFile      string `yaml:"log_file,omitempty"`
	ListenPort   int    `yaml:"port,omitempty"`
	ListenIP     string `yaml:"ip,omitempty"`
	HttpPort     uint16 `yaml:"http_port,omitempty"`
	HttpsPort    uint16 `yaml:"https_port,omitempty"`
	ServerDomain string `yaml:"server_domain,omitempty"`
	TlsCert      string `yaml:"tls_cert,omitempty"`
	TlsKey       string `yaml:"tls_key,omitempty"`
	SecretKey    string `yaml:"secret_key,omitempty"`
	//none:means no encrypt
	//aes:means exchange premaster key in aes mode
	//tls:means exchange premaster key in tls mode
	//default value is tls
	EncryptMode  string `yaml:"encrypt_mode,omitempty"`
	AuthEnable   bool   `yaml:"auth_enable,omitempty"`
	AuthUrl      string `yaml:"auth_url,omitempty"`
	NotifyEnable bool   `yaml:"notify_enable,omitempty"`
	NotifyUrl    string `yaml:"notify_url,omitempty"`
}

var serverConf Config

func LoadConfig(configFile string) error {
	if configFile != "" {
		content, err := ioutil.ReadFile(configFile)
		if err != nil {
			return errors.Wrap(err, "read config file")
		}
		if strings.HasSuffix(configFile, "json") {
			err = json.Unmarshal(content, &serverConf)
			if err != nil {
				return errors.Wrap(err, "unmarshal config file using json decode")
			}
		} else {
			err = yaml.Unmarshal(content, &serverConf)
			if err != nil {
				return errors.Wrap(err, "unmarshal config file using yaml decode")
			}
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
