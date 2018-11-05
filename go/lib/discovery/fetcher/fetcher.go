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
	"github.com/scionproto/scion/go/lib/discovery/pool"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ discovery.Fetcher = (*Fetcher)(nil)

// Callbacks are used to inform the client. The functions are called when
// the an associated event occurs. If the function is nil, it is ignored.
type Callbacks struct {
	// Raw is called with the raw body from the discovery service response.
	Raw func(common.RawBytes)
	// Update is called with the parsed topology from the discovery service response.
	Update func(*topology.Topo)
	// Error is called with any error that occurs.
	Error func(error)
}

// Fetcher is used to fetch a new topology file from the discovery service.
type Fetcher struct {
	// Pool is a Pool of discovery services
	Pool discovery.Pool
	// Callbacks contains the callbacks.
	Callbacks Callbacks
	// Client is the http Client. If nil, the default Client is used.
	Client *http.Client
	// Mode indicates whether the static or the dynamic topology is requested.
	Mode discovery.Mode
	// File indicates whether the full or the reduced topology is requested.
	// The full topology requires that this host is on the ACL of the contacted DS server.
	File discovery.File
	// Https indicates if https must be used.
	Https bool
}

// New initializes a fetcher with the given values. Topo is provided to
// initialize the pool with discovery services.
func New(mode discovery.Mode, file discovery.File, https bool, topo *topology.Topo,
	client *http.Client, clbks Callbacks) (*Fetcher, error) {

	var err error
	f := &Fetcher{
		Callbacks: clbks,
		Client:    client,
		Mode:      mode,
		File:      file,
		Https:     https,
	}
	if f.Pool, err = pool.New(topo); err != nil {
		return nil, err
	}
	return f, nil
}

// UpdateTopo updates the topology for the fetcher. This allows changing
// the discovery service pool.
func (f *Fetcher) UpdateTopo(topo *topology.Topo) error {
	return f.Pool.Update(topo)
}

// Run fetches a new topology file from the discovery service and calls the
// appropriate callback functions to notify the caller. RawF and UpdateF are
// only called if no error has occurred and the topology was parsed correctly.
// Otherwise ErrorF is called.
func (f *Fetcher) Run(ctx context.Context) {
	if err := f.run(ctx); err != nil {
		f.error(err)
	}
}

func (f *Fetcher) run(ctx context.Context) error {
	if f.Pool == nil {
		return common.NewBasicError("Fetcher not initialized", nil)
	}
	// Choose a DS server.
	ds, err := f.Pool.Choose()
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
	if err := f.Pool.Update(topo); err != nil {
		return common.NewBasicError("Unable to update pool", err)
	}
	// Notify the client.
	f.raw(raw)
	f.update(topo)
	return nil
}

func (f *Fetcher) raw(raw common.RawBytes) {
	if f.Callbacks.Raw != nil {
		f.Callbacks.Raw(raw)
	}
}

func (f *Fetcher) update(topo *topology.Topo) {
	if f.Callbacks.Update != nil {
		f.Callbacks.Update(topo)
	}
}

func (f *Fetcher) error(err error) {
	if f.Callbacks.Error != nil {
		f.Callbacks.Error(err)
	}
}
