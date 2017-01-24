package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/Sirupsen/logrus"
)

type Config struct {
	Prod        bool
	LogFile     string
	ControlAddr string
	TunnelAddr  string
}

func LoadConfig(configFile string) *Config {
	var conf Config
	if configFile != "" {
		content, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Fatalf("read config file (%s) failed!err:=%v", configFile, err)
			return nil
		}
		err = json.Unmarshal(content, &conf)
		if err != nil {
			log.Fatalf("unmarshal config (%v) into golang struct failed!err:=%v", string(content), err)
			return nil
		}
	}
	if conf.ControlAddr == "" {
		conf.ControlAddr = "0.0.0.0:8080"
	}
	if conf.TunnelAddr == "" {
		conf.TunnelAddr = "0.0.0.0:8081"
	}
	return &conf
}

func InitLog(conf *Config) {
	if conf.Prod {
		logrus.SetLevel(logrus.WarnLevel)
	} else {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if conf.LogFile != "" {
		f, err := os.OpenFile(conf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
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
