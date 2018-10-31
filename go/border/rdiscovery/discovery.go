// Copyright 2018 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rdiscovery

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/scionproto/scion/go/border/conf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/discovery/topofetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
)

var (
	// Rate is the time between requests to the discovery service.
	Rate = 5 * time.Second
	// Timeout is the timeout for a request to the discovery service.
	Timeout = 2 * time.Second
)

// FetchTopo periodically fetches a new topology file from the discovery service
// and updates the config accordingly.
func FetchTopo(id string, setCtx func(*rctx.Ctx) error, sig <-chan struct{}) {
	t := &task{
		Logger: log.New("Part", "Discovery"),
		id:     id,
		setCtx: setCtx,
	}
	t.Info("Starting periodic topology update")
	periodic.StartPeriodicTask(t, periodic.NewTicker(Rate), Timeout)
	// Update topology when a sighup is received.
	for range sig {
		if t.fetcher != nil {
			t.fetcher.UpdateInstances(rctx.Get().Conf.Topo.DS)
		}
	}
}

var _ periodic.Task = (*task)(nil)

type task struct {
	log.Logger
	// id is the router id.
	id string
	// setCtx is the callback to set the context for a router.
	setCtx func(*rctx.Ctx) error
	// fetcher is the discovery service fetcher
	fetcher *topofetcher.Fetcher
	// localAddr is the local control address. When changed, the fetcher
	// http client is changed and runner needs to be restarted.
	localAddr string
}

func (t *task) Run(ctx context.Context) {
	if err := t.run(ctx); err != nil {
		log.Error("Unable to fetch topology", "err", err)
	}
}

func (t *task) run(ctx context.Context) error {
	rCtx := rctx.Get()
	if t.fetcher == nil {
		var err error
		t.fetcher, err = topofetcher.New(
			rCtx.Conf.Topo.DS,
			discovery.FetchParams{
				Mode: discovery.Dynamic,
				File: discovery.Full,
			},
			topofetcher.Callbacks{
				Error:  t.handleErr,
				Update: t.handleTopo,
			},
			nil,
		)
		if err != nil {
			return common.NewBasicError("Unable to initialize fetcher", err)
		}
	}
	localAddr, err := getLocalAddr(rCtx)
	if err != nil {
		return common.NewBasicError("Unable to get local address", err)
	}
	if t.localAddr != localAddr {
		if t.fetcher.Client, err = client(localAddr); err != nil {
			return common.NewBasicError("Unable to create client", err)
		}
	}
	t.fetcher.Run(ctx)
	return nil
}

// handleErr is the callback for the topology fetcher.
func (t *task) handleErr(err error) {
	t.Error("Unable to fetch new topology", "err", err)
}

// handleTopo is the callback for the topology fetcher.
func (t *task) handleTopo(topo *topology.Topo) {
	if err := t.handleTopoE(topo); err != nil {
		log.Error("Unable to handle topology", "err", err)
	}
}

func (t *task) handleTopoE(topo *topology.Topo) error {
	// Make sure border router is still in the toplogy. Otherwise,
	// the topology is rejected.
	if _, ok := topo.BR[t.id]; !ok {
		return common.NewBasicError("Unable to find element ID in topology", nil, "id", t.id)
	}
	// Avoid race with sighup reloading.
	rctx.SetLock.Lock()
	defer rctx.SetLock.Unlock()
	oldCtx := rctx.Get()

	cfg := &conf.Conf{
		Dir:        oldCtx.Conf.Dir,
		ASConf:     oldCtx.Conf.ASConf,
		MasterKeys: oldCtx.Conf.MasterKeys,
	}
	if err := cfg.InitTopo(t.id, topo); err != nil {
		return common.NewBasicError("Unable to initialize topology", err)
	}
	if err := cfg.InitNet(); err != nil {
		return common.NewBasicError("Unable to initialize network config", err)
	}
	if err := cfg.InitMacPool(); err != nil {
		return common.NewBasicError("Unable to initialize mac pool", err)
	}
	if err := t.setCtx(rctx.New(cfg)); err != nil {
		return common.NewBasicError("Unable to set context", err)
	}
	return nil
}

func client(localAddr string) (*http.Client, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", localAddr+":0")
	if err != nil {
		return nil, err
	}
	// The border router needs to use the correct source address to make sure
	// it is on the ACL. The local address is set to ctrl address of the border router.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: tcpAddr,
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	return client, nil
}

// getLocalAddr gets the local control address.
func getLocalAddr(ctx *rctx.Ctx) (string, error) {
	if _, ok := ctx.Conf.Topo.IFInfoMap[ctx.Conf.BR.IFIDs[0]]; !ok {
		return "", common.NewBasicError("Missing ifid info", nil, "ifid", ctx.Conf.BR.IFIDs[0])
	}
	ctrl := ctx.Conf.Topo.IFInfoMap[ctx.Conf.BR.IFIDs[0]].CtrlAddrs
	return ctrl.PublicAddr(ctrl.Overlay).L3.String(), nil
}
