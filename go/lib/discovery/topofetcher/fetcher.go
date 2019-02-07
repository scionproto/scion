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

package topofetcher

import (
	"context"
	"net/http"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/discovery/discoverypool"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ discovery.Fetcher = (*Fetcher)(nil)

// Callbacks are used to inform the client. The functions are called when
// an associated event occurs. If the function is nil, it is ignored.
type Callbacks struct {
	// Raw is called with the raw body from the discovery service response and the parsed topology.
	Raw func(common.RawBytes, *topology.Topo)
	// Update is called with the parsed topology from the discovery service response.
	Update func(*topology.Topo)
	// Error is called with any error that occurs.
	Error func(error)
}

// Fetcher is used to fetch a new topology file from the discovery service.
type Fetcher struct {
	// Pool is a Pool of discovery services
	Pool discovery.InstancePool
	// Params contains the parameters for fetching the topology.
	Params discovery.FetchParams
	// Callbacks contains the callbacks.
	Callbacks Callbacks
	// Client is the http Client. If nil, the default Client is used.
	Client *http.Client
}

// New initializes a fetcher with the given values. Topo is provided to
// initialize the pool with discovery services.
func New(svcInfo topology.IDAddrMap, params discovery.FetchParams,
	clbks Callbacks, client *http.Client) (*Fetcher, error) {

	var err error
	f := &Fetcher{
		Params:    params,
		Callbacks: clbks,
		Client:    client,
	}
	if f.Pool, err = discoverypool.New(svcInfo); err != nil {
		return nil, err
	}
	return f, nil
}

// UpdateInstances updates the discovery service pool.
func (f *Fetcher) UpdateInstances(svcInfo topology.IDAddrMap) error {
	return f.Pool.Update(svcInfo)
}

// Run fetches a new topology file from the discovery service and calls the
// appropriate callback functions to notify the caller. RawF and UpdateF are
// only called if no error has occurred and the topology was parsed correctly.
// Otherwise ErrorF is called.
func (f *Fetcher) Run(ctx context.Context) {
	if err := f.run(ctx); err != nil && f.Callbacks.Error != nil {
		f.Callbacks.Error(err)
	}
}

func (f *Fetcher) run(ctx context.Context) error {
	if f.Pool == nil {
		return common.NewBasicError("Pool not initialized", nil)
	}
	// Choose a DS server.
	ds, err := f.Pool.Choose()
	if err != nil {
		return err
	}
	topo, raw, err := discovery.FetchTopoRaw(ctx, f.Params, ds.Addr(), f.Client)
	if err != nil {
		ds.Fail()
		return err
	}
	// Update DS server entries based on new topo.
	err = f.Pool.Update(topo.DS)
	if err != nil {
		return common.NewBasicError("Unable to update pool", err)
	}
	// Notify the client.
	if f.Callbacks.Raw != nil {
		f.Callbacks.Raw(raw, topo)
	}
	if f.Callbacks.Update != nil {
		f.Callbacks.Update(topo)
	}
	return nil
}
