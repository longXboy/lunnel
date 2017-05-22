// Copyright 2017 longXboy, longxboyhi@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"crypto/sha1"
	"encoding/json"
	"net"
	"os"

	"github.com/longXboy/lunnel/log"
	"github.com/longXboy/lunnel/util"
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

type TunnelConfig struct {
	Schema          string `yaml:"schema,omitempty"`
	Host            string `yaml:"host,omitempty"`
	Port            uint16 `yaml:"port,omitempty"`
	LocalAddr       string `yaml:"local,omitempty"`
	HttpHostRewrite string `yaml:"http_host_rewrite,omitempty"`
	HttpsSkipVerify bool   `yaml:"https_skip_verify,omitempty"`
}

type Health struct {
	Interval int64 `yaml:"interval,omitempty"`
	TimeOut  int64 `yaml:"timeout,omitempty"`
}

type Config struct {
	Debug    bool   `yaml:"debug,omitempty"`
	LogFile  string `yaml:"log_file,omitempty"`
	ClientId string `yaml:"id,omitempty"`
	//if EncryptMode is tls and ServerName is empty,ServerAddr can't be IP format
	ServerAddr    string `yaml:"server_addr"`
	ServerUdpAddr string `yaml:"server_udp_addr"`
	ServerTcpAddr string `yaml:"server_tcp_addr"`
	Aes           Aes    `yaml:"aes,omitempty"`
	Tls           Tls    `yaml:"tls,omitempty"`
	EncryptMode   string `yaml:"encrypt_mode,omitempty"`
	//none:no encryption
	//aes:encrpted by aes
	//tls:encrpted by tls,which is default
	Tunnels   map[string]TunnelConfig `yaml:"tunnels"`
	AuthToken string                  `yaml:"auth_token,omitempty"`
	//mix: switch between kcp and tcp automatically,which is default
	//kcp: communicate with server in kcp
	//tcp: communicate with server in tcp
	Transport      string `yaml:"transport,omitempty"`
	HttpProxy      string `yaml:"http_proxy,omitempty"`
	DSN            string `yaml:"dsn,omitempty"`
	EnableCompress bool   `yaml:"enable_compress,omitempty"`
	Durable        bool   `yaml:"durable,omitempty"`
	DurableFile    string `yaml:"durable_file,omitempty"`
	Health         Health `yaml:"health,omitempty"`
	ManagePort     uint16 `yaml:"manage_port,omitempty"`
	DisableManage  bool   `yaml:"disable_manage,omitempty"`
}

var cliConf Config

func LoadConfig(configDetail []byte, configType string) error {
	var err error
	if len(configDetail) > 0 {
		if configType == "json" {
			err = json.Unmarshal(configDetail, &cliConf)
			if err != nil {
				return errors.Wrap(err, "unmarshal config file using json decode")
			}
		} else {
			err = yaml.Unmarshal(configDetail, &cliConf)
			if err != nil {
				return errors.Wrap(err, "unmarshal config file using yaml decode")
			}
		}
	}
	if cliConf.ServerAddr == "" {
		cliConf.ServerAddr = "example.com:8080"
	}
	if cliConf.ServerAddr != "" {
		if cliConf.ServerUdpAddr == "" {
			cliConf.ServerUdpAddr = cliConf.ServerAddr
		}
		if cliConf.ServerTcpAddr == "" {
			cliConf.ServerTcpAddr = cliConf.ServerAddr
		}
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
	if cliConf.HttpProxy != "" {
		if cliConf.Transport == "kcp" {
			return errors.Errorf("can't set transport mode kcp and http_proxy at same time")
		}
		cliConf.Transport = "tcp"
	}
	if cliConf.DSN == "" {
		cliConf.DSN = "https://22946d46117c4bac9e680bf10597c564:e904ecd5c94e46c2aa9d15dcae90ac80@sentry.io/156456"
	}

	if len(cliConf.Tunnels) == 0 {
		log.Warningln("no proxying tunnels sepcified!")
	} else {
		for name, tunnel := range cliConf.Tunnels {
			localSchema, localHost, _, err := util.ParseAddr(tunnel.LocalAddr)
			if err != nil {
				return errors.Wrapf(err, "parse %s local_address", name)
			}
			if localHost == "" {
				return errors.Errorf("%s local_host can not be empty", name)
			}
			if localSchema == "" {
				if tunnel.Schema != "" {
					localSchema = tunnel.Schema
				} else {
					localSchema = "tcp"
				}
				tunnel.LocalAddr = localSchema + "://" + tunnel.LocalAddr
			}
			if tunnel.Schema == "" {
				tunnel.Schema = localSchema
			}
			if tunnel.Port > 65535 {
				return errors.Errorf("%s public_port can not greater than 65535", name)
			}
			cliConf.Tunnels[name] = tunnel
		}
	}
	if cliConf.Durable {
		if cliConf.DurableFile == "" {
			cliConf.DurableFile = "./lunnel.id"
		}
	}
	if cliConf.Health.Interval == 0 {
		cliConf.Health.Interval = 30
	}
	if cliConf.Health.TimeOut == 0 {
		cliConf.Health.TimeOut = 65
	}
	if cliConf.ManagePort == 0 {
		cliConf.ManagePort = 8082
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
