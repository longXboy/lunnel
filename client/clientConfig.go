package client

import (
	"crypto/sha1"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/longXboy/Lunnel/log"
	"github.com/longXboy/Lunnel/msg"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v2"
)

type Aes struct {
	SecretKey string `yaml:"secret_key,omitempty"`
}

type Tls struct {
	TrustedCert string `yaml:"trusted_cert,omitempty"`
	ServerName  string `yaml:"server_name,omitempty"`
}

type Config struct {
	Debug   bool   `yaml:"debug,omitempty"`
	LogFile string `yaml:"log_file,omitempty"`
	//if EncryptMode is tls and ServerName is empty,ServerAddr can't be IP format
	ServerAddr  string `yaml:"server_addr"`
	Aes         Aes    `yaml:"aes,omitempty"`
	Tls         Tls    `yaml:"tls,omitempty"`
	EncryptMode string `yaml:"encrypt_mode,omitempty"`
	//none:no encryption
	//aes:encrpted by aes
	//tls:encrpted by tls,which is default
	Tunnels   map[string]msg.TunnelConfig `yaml:"tunnels"`
	AuthToken string                      `yaml:"auth_token,omitempty"`
	//mix: switch between kcp and tcp automatically,which is default
	//kcp: communicate with server in kcp
	//tcp: communicate with server in tcp
	Transport      string `yaml:"transport,omitempty"`
	HttpProxy      string `yaml:"http_proxy,omitempty"`
	DSN            string `yaml:"dsn,omitempty"`
	EnableCompress bool   `yaml:"enable_compress,omitempty"`
}

var cliConf Config

func LoadConfig(configFile string) error {
	if configFile != "" {
		content, err := ioutil.ReadFile(configFile)
		if err != nil {
			return errors.Wrap(err, "read config file")
		}
		if strings.HasSuffix(configFile, "json") {
			err = json.Unmarshal(content, &cliConf)
			if err != nil {
				return errors.Wrap(err, "unmarshal config file using json decode")
			}
		} else {
			err = yaml.Unmarshal(content, &cliConf)
			if err != nil {
				return errors.Wrap(err, "unmarshal config file using yaml decode")
			}
		}
	}
	if cliConf.ServerAddr == "" {
		cliConf.ServerAddr = "example.com:8080"
	}
	if cliConf.EncryptMode == "" {
		if cliConf.Aes.SecretKey != "" {
			cliConf.EncryptMode = "aes"
		}
		if cliConf.Tls.TrustedCert != "" || cliConf.Tls.ServerName != "" {
			cliConf.EncryptMode = "tls"
		}
		if cliConf.EncryptMode == "" {
			cliConf.EncryptMode = "none"
		}
	}
	if cliConf.EncryptMode == "aes" {
		if cliConf.Aes.SecretKey == "" {
			log.Fatalln("client can't start AES mode without configuring SecretKey")
		}
		pass := pbkdf2.Key([]byte(cliConf.Aes.SecretKey), []byte("lunnel"), 4096, 32, sha1.New)
		cliConf.Aes.SecretKey = string(pass[:16])
	} else if cliConf.EncryptMode == "tls" {
		if cliConf.Tls.ServerName == "" {
			var err error
			cliConf.Tls.ServerName, err = resovleServerName(cliConf.ServerAddr)
			if err != nil {
				return errors.Wrap(err, "resovleServerName")
			}
		}
	} else if cliConf.EncryptMode == "none" {
		log.Warningln("no tranport encryption secified,it may be not safe")
	} else {
		log.Fatalln("invalid encyption:", cliConf.EncryptMode)
	}
	if len(cliConf.Tunnels) == 0 {
		log.Warningln("no proxying tunnels sepcified")
	}
	if cliConf.Transport == "" {
		cliConf.Transport = "mix"
	} else if cliConf.Transport != "kcp" && cliConf.Transport != "tcp" && cliConf.Transport != "mix" {
		return errors.Errorf("invalid transport mode:%s", cliConf.Transport)
	}
	if (os.Getenv("http_proxy") != "" || os.Getenv("HTTP_PROXY") != "") && cliConf.HttpProxy == "" {
		if os.Getenv("http_proxy") != "" {
			cliConf.HttpProxy = os.Getenv("http_proxy")
		} else if os.Getenv("HTTP_PROXY") != "" {
			cliConf.HttpProxy = os.Getenv("HTTP_PROXY")
		}
	}
	if cliConf.DSN == "" {
		cliConf.DSN = "https://22946d46117c4bac9e680bf10597c564:e904ecd5c94e46c2aa9d15dcae90ac80@sentry.io/156456"
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
