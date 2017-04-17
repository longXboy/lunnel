package server

import (
	"crypto/sha1"
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/longXboy/lunnel/log"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v2"
)

type Aes struct {
	SecretKey string `yaml:"secret_key,omitempty"`
}

type Tls struct {
	TlsCert string `yaml:"cert,omitempty"`
	TlsKey  string `yaml:"key,omitempty"`
}

type Health struct {
	Interval int64 `yaml:"interval,omitempty"`
	TimeOut  int64 `yaml:"timeout,omitempty"`
}

type Config struct {
	Debug        bool   `yaml:"debug,omitempty"`
	LogFile      string `yaml:"log_file,omitempty"`
	ListenPort   int    `yaml:"port,omitempty"`
	ListenIP     string `yaml:"ip,omitempty"`
	HttpPort     uint16 `yaml:"http_port,omitempty"`
	HttpsPort    uint16 `yaml:"https_port,omitempty"`
	ManagePort   uint16 `yaml:"manage_port,omitempty"`
	ServerDomain string `yaml:"server_domain,omitempty"`
	Aes          Aes    `yaml:"aes,omitempty"`
	Tls          Tls    `yaml:"tls,omitempty"`
	AuthEnable   bool   `yaml:"auth_enable,omitempty"`
	AuthUrl      string `yaml:"auth_url,omitempty"`
	NotifyEnable bool   `yaml:"notify_enable,omitempty"`
	NotifyUrl    string `yaml:"notify_url,omitempty"`
	NotifyKey    string `yaml:"notify_key,omitempty"`
	DSN          string `yaml:"dsn,omitempty"`
	Health       Health `yaml:"health,omitempty"`
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
	if serverConf.ManagePort == 0 {
		serverConf.ManagePort = 8081
	}
	if serverConf.Aes.SecretKey != "" {
		pass := pbkdf2.Key([]byte(serverConf.Aes.SecretKey), []byte("lunnel"), 4096, 32, sha1.New)
		serverConf.Aes.SecretKey = string(pass[:16])
	} else {
		log.Warningln("server can not support AES mode without configuring AES's secretkey")
	}
	if serverConf.ServerDomain == "" {
		log.Warningln("server may not proxy http or https req correctly without configuring ServerDomain")
	}
	if serverConf.DSN == "" {
		serverConf.DSN = "https://22946d46117c4bac9e680bf10597c564:e904ecd5c94e46c2aa9d15dcae90ac80@sentry.io/156456"
	}
	if serverConf.Health.Interval == 0 {
		serverConf.Health.Interval = 20
	}
	if serverConf.Health.TimeOut == 0 {
		serverConf.Health.TimeOut = 50
	}
	return nil
}
