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

package fetcher

import (
	"context"
	"net/http"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/discovery/info"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ discovery.Fetcher = (*Fetcher)(nil)

// Fetcher is used to fetch a new topology file from the discovery service.
type Fetcher struct {
	// pool is a pool of discovery services
	pool discovery.Pool
	// Client is the http client. If nil, the default client is used.
	Client *http.Client
	// RawF is the callback to get the raw body from the DS response. Can be nil.
	RawF func(common.RawBytes)
	// UpdateF is the callback to get the parsed topology from the DS response. Can be nil.
	UpdateF func(*topology.Topo)
	// ErrorF is the callback to get all errors that occure. Can be nil.
	ErrorF func(error)
	// Https indicates if https must be used.
	Https bool
	// Mode indicates whether the static or the dynamic topology is requested.
	Mode discovery.Mode
	// File indicates whether the full or the reduced topology is requested.
	// The full topology requires that this host is on the ACL of the contacted DS server.
	File discovery.File
}

// Init initializes the fetcher. It must be called at least once before Run.
func (f *Fetcher) Init(topo *topology.Topo) error {
	var err error
	if f.pool, err = info.NewPool(topo); err != nil {
		return err
	}
	return nil
}

// UpdateTopo updates the topology for the fetcher. This allows changing
// the discovery service pool.
func (f *Fetcher) UpdateTopo(topo *topology.Topo) error {
	return f.pool.Update(topo)
}

// Run fetches a new topology file from the discovery service and calls the
// appropriate callback functions to notify the caller. RawF and UpdateF are
// only called if no error has occurred and the topology was parsed correctly.
// Otherwise ErrorF is called.
func (f *Fetcher) Run(ctx context.Context) {
	if err := f.run(ctx); err != nil {
		f.errorF(err)
	}
}

func (f *Fetcher) run(ctx context.Context) error {
	if f.pool == nil {
		return common.NewBasicError("Fetcher not initialized", nil)
	}
	// Choose a DS server.
	ds, err := f.pool.Choose()
	if err != nil {
		return err
	}
	topo, raw, err := discovery.TopoRaw(ctx, f.Client,
		discovery.CreateURL(ds.Addr(), f.Mode, f.File, f.Https))
	if err != nil {
		ds.Fail()
		return err
	}
	// Update DS server entries based on new topo.
	if err := f.pool.Update(topo); err != nil {
		return common.NewBasicError("Unable to update pool", err)
	}
	// Notify the client.
	f.rawF(raw)
	f.updateF(topo)
	return nil
}

func (f *Fetcher) rawF(raw common.RawBytes) {
	if f.RawF != nil {
		f.RawF(raw)
	}
}

func (f *Fetcher) updateF(topo *topology.Topo) {
	if f.UpdateF != nil {
		f.UpdateF(topo)
	}
}

func (f *Fetcher) errorF(err error) {
	if f.ErrorF != nil {
		f.ErrorF(err)
	}
}
