package main

import (
	"Lunnel/msg"
	"encoding/json"
	"io/ioutil"
	rawLog "log"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

type Config struct {
	Prod        bool
	LogFile     string
	ControlAddr string
	TunnelAddr  string
	//if TrustedCert is specified,you must supply ServerDomain
	ServerDomain   string
	SelfSignedCert bool
	//trusted root CA cert
	TrustedCert string
	SecretKey   string
	//none:means no encrypt
	//aes:means exchange premaster key in aes mode
	//tls:means exchange premaster key in tls mode
	//default value is tls
	EncryptMode  string
	Tunnels      []msg.Tunnel
	ConnRetryGap int64
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
	if cliConf.ControlAddr == "" {
		cliConf.ControlAddr = "lunnel.snakeoil.com:8080"
	}
	if cliConf.TunnelAddr == "" {
		cliConf.TunnelAddr = "lunnel.snakeoil.com:8081"
	}
	if cliConf.EncryptMode == "" {
		cliConf.EncryptMode = "tls"
	}
	if cliConf.EncryptMode == "tls" {
		if cliConf.SelfSignedCert {
			if cliConf.TrustedCert == "" {
				cliConf.TrustedCert = "../assets/client/cacert.pem"
				cliConf.ServerDomain = "lunnel.snakeoil.com"
			} else {
				if cliConf.ServerDomain == "" {
					return errors.Errorf("you must specify ServerDomain while using SelfSignedCert mode")
				}
			}
		}
	}
	if cliConf.ConnRetryGap == 0 {
		cliConf.ConnRetryGap = 3
	}
	if cliConf.Tunnels == nil || len(cliConf.Tunnels) == 0 {
		return errors.Errorf("you must specify at least one tunnel")
	}
	return nil
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
