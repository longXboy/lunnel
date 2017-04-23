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

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"strings"

	"github.com/longXboy/lunnel/server"
)

func main() {
	configFile := flag.String("c", "./config.yml", "path of config file")
	flag.Parse()
	var configDetail []byte
	var err error
	configType := ""
	if *configFile != "" {
		configDetail, err = ioutil.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("read configfile failed!err:=%v\n", err)
			return
		}
		if strings.HasSuffix(*configFile, "json") {
			configType = "json"
		} else {
			configType = "yaml"
		}
	}

	server.Main(configDetail, configType)
}
