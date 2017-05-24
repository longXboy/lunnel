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
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/e-dard/netbug"
	"github.com/longXboy/lunnel/log"
	"github.com/longXboy/lunnel/msg"
	"github.com/satori/go.uuid"
	"gopkg.in/gin-gonic/gin.v1"
)

type tunnelStateReq struct {
	PublicUrl string
}

type tunnelStateResp struct {
	Tunnels []string
}

type clientState struct {
	Id             string
	LastRead       uint64
	EncryptMode    string
	EnableCompress bool
	Version        string
	Tunnels        map[string]tunnelState
	TotalPipes     uint32
	BusyPipes      uint32
	IdlePipes      uint32
}

type tunnelState struct {
	ClientId string `json:",omitempty"`
	Tunnel   msg.Tunnel
	IsClosed bool
}

type clientStateResp struct {
	Clients []clientState
}

func listenAndServeManage() {
	if serverConf.Debug {
		gin.SetMode("debug")
	} else {
		gin.SetMode("release")
	}
	r := gin.New()
	r.GET("/v1/tunnels", tunnelsQuery)
	r.POST("/v1/tunnels", tunnelQuery)
	r.GET("/v1/clients", clientsQuery)
	r.GET("/v1/clients/clientId", clientQuery)

	mux := http.NewServeMux()
	if serverConf.PProfEnable {
		netbug.RegisterHandler("/debug/pprof/", mux)
	}
	mux.Handle("/v1/", r)

	log.WithFields(log.Fields{"addr": fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.ManagePort)}).Infoln("start to listen and serve manage")
	err := http.ListenAndServe(fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.ManagePort), mux)
	if err != nil {
		log.WithFields(log.Fields{"addr": fmt.Sprintf("%s:%d", serverConf.ListenIP, serverConf.ManagePort), "err": err.Error()}).Infoln("listen and serve manage failed!")
	}
}

func tunnelQuery(c *gin.Context) {
	var query tunnelStateReq
	err := c.BindJSON(&query)
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("unmarshal req body failed!"))
		return
	}

	var tunnelStats tunnelStateResp = tunnelStateResp{Tunnels: []string{}}
	if query.PublicUrl != "" {
		TunnelMapLock.RLock()
		tunnel, isok := TunnelMap[query.PublicUrl]
		TunnelMapLock.RUnlock()
		if isok {
			tunnelStats.Tunnels = append(tunnelStats.Tunnels, tunnel.tunnelConfig.PublicAddr())
		}
	}

	c.JSON(http.StatusOK, tunnelStats)
}

func tunnelsQuery(c *gin.Context) {
	var tunnelStats tunnelStateResp = tunnelStateResp{Tunnels: []string{}}

	TunnelMapLock.RLock()
	for _, v := range TunnelMap {
		tunnelStats.Tunnels = append(tunnelStats.Tunnels, v.tunnelConfig.PublicAddr())
	}
	TunnelMapLock.RUnlock()

	c.JSON(http.StatusOK, tunnelStats)
}

func clientQuery(c *gin.Context) {
	clientId := c.Param("clientId")
	uuid, err := uuid.FromString(clientId)
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("invalid uuid"))
		return
	}
	var clientStates clientStateResp = clientStateResp{Clients: []clientState{}}
	ControlMapLock.RLock()
	ctlClient := ControlMap[uuid]
	ControlMapLock.RUnlock()
	var client clientState
	client.LastRead = atomic.LoadUint64(&client.LastRead)
	client.TotalPipes = atomic.LoadUint32(&ctlClient.totalPipes)
	client.Tunnels = make(map[string]tunnelState)
	ctlClient.tunnelLock.Lock()
	for _, v := range ctlClient.tunnels {
		client.Tunnels[v.name] = tunnelState{Tunnel: v.tunnelConfig, IsClosed: v.isClosed}
	}
	ctlClient.tunnelLock.Unlock()
	client.EnableCompress = ctlClient.enableCompress
	client.EncryptMode = ctlClient.encryptMode
	client.Id = ctlClient.ClientID.String()
	client.Version = ctlClient.version
	clientStates.Clients = append(clientStates.Clients, client)
	c.JSON(http.StatusOK, clientStates)
}

func clientsQuery(c *gin.Context) {
	var clientStates clientStateResp = clientStateResp{Clients: []clientState{}}
	clients := make([]*Control, 0)
	ControlMapLock.RLock()
	for _, v := range ControlMap {
		clients = append(clients, v)
	}
	ControlMapLock.RUnlock()
	for _, c := range clients {
		var client clientState
		client.LastRead = atomic.LoadUint64(&c.lastRead)
		client.TotalPipes = atomic.LoadUint32(&c.totalPipes)
		client.BusyPipes = atomic.LoadUint32(&c.busyPipeCount)
		client.IdlePipes = atomic.LoadUint32(&c.idlePipeCount)
		client.Tunnels = make(map[string]tunnelState)
		c.tunnelLock.Lock()
		for _, v := range c.tunnels {
			client.Tunnels[v.name] = tunnelState{Tunnel: v.tunnelConfig, IsClosed: v.isClosed, ClientId: v.ctl.ClientID.String()}
		}
		c.tunnelLock.Unlock()
		client.EnableCompress = c.enableCompress
		client.EncryptMode = c.encryptMode
		client.Id = c.ClientID.String()
		client.Version = c.version
		clientStates.Clients = append(clientStates.Clients, client)
	}
	c.JSON(http.StatusOK, clientStates)
}
