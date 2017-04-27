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

package server

import (
	"crypto/sha1"
	"encoding/json"
	"strconv"

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
	MaxIdlePipes string `yaml:"max_idle_pipes,omitempty"`
	MaxStreams   string `yaml:"max_streams,omitempty"`
}

var serverConf Config

func LoadConfig(configDetail []byte, configType string) error {
	var err error
	if len(configDetail) > 0 {
		if configType == "json" {
			err = json.Unmarshal(configDetail, &serverConf)
			if err != nil {
				return errors.Wrap(err, "unmarshal config file using json decode")
			}
		} else {
			err = yaml.Unmarshal(configDetail, &serverConf)
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
	if serverConf.MaxIdlePipes == "" {
		serverConf.MaxIdlePipes = "4"
	} else {
		_, err := strconv.ParseUint(serverConf.MaxIdlePipes, 10, 64)
		if err != nil {
			log.Fatalln("max_idle_pipes must be an unsigned integer")
		}
	}
	if serverConf.MaxStreams == "" {
		serverConf.MaxStreams = "6"
	} else {
		_, err := strconv.ParseUint(serverConf.MaxStreams, 10, 64)
		if err != nil {
			log.Fatalln("max_streams must be an unsigned integer")
		}
	}

	return nil
}
