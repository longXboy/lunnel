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
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/longXboy/lunnel/log"
	"github.com/longXboy/lunnel/msg"
	"github.com/satori/go.uuid"
)

type tunnelStateReq struct {
	PublicUrl string
}

func (u *tunnelStateReq) Bind(r *http.Request) error {
	return nil
}

type tunnelStateResp string

func (rd *tunnelStateResp) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
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

func (rd *clientState) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type tunnelState struct {
	ClientId string `json:",omitempty"`
	Tunnel   msg.Tunnel
	IsClosed bool
}

func listenAndServeManage() {
	r := chi.NewRouter()
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	r.Get("/v1/tunnels", tunnelsQuery)
	r.Post("/v1/tunnels", tunnelQuery)
	r.Get("/v1/clients", clientsQuery)
	r.Get("/v1/clients/clientId", clientQuery)

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

func tunnelQuery(w http.ResponseWriter, r *http.Request) {
	var query tunnelStateReq
	err := render.Bind(r, &query)
	if err != nil {
		http.Error(w, "unmarshal req body failed!", http.StatusBadRequest)
		return
	}
	var tunnelStats []render.Renderer
	if query.PublicUrl != "" {
		TunnelMapLock.RLock()
		tunnel, isok := TunnelMap[query.PublicUrl]
		TunnelMapLock.RUnlock()
		if isok {
			r := tunnelStateResp(tunnel.tunnelConfig.PublicAddr())
			tunnelStats = append(tunnelStats, &r)
		}
	}
	render.RenderList(w, r, tunnelStats)
}

func tunnelsQuery(w http.ResponseWriter, r *http.Request) {
	var tunnelStats []render.Renderer

	TunnelMapLock.RLock()
	for _, v := range TunnelMap {
		r := tunnelStateResp(v.tunnelConfig.PublicAddr())
		tunnelStats = append(tunnelStats, &r)
	}
	TunnelMapLock.RUnlock()

	render.RenderList(w, r, tunnelStats)
}

func clientQuery(w http.ResponseWriter, r *http.Request) {
	clientId := chi.URLParam(r, "clientId")
	uuid, err := uuid.FromString(clientId)
	if err != nil {
		http.Error(w, "invalid uuid!", http.StatusBadRequest)
		return
	}
	var clientStates []render.Renderer
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
	clientStates = append(clientStates, &client)
	render.RenderList(w, r, clientStates)
}

func clientsQuery(w http.ResponseWriter, r *http.Request) {
	var clientStates []render.Renderer
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
		clientStates = append(clientStates, &client)
	}
	render.RenderList(w, r, clientStates)
}
