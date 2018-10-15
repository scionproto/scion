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

package discovery

import (
	"context"
	"net/http"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ periodic.Task = (*Fetcher)(nil)

// Fetcher is used to fetch a new topology file from the discovery service.
type Fetcher struct {
	// Pool is a pool of DS servers. It must be initialized
	// with at least one DS server. The pool is managed by
	// Fetcher.
	Pool Pool
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
	// Dynamic indicates if the dynamic topology is requested.
	Dynamic bool
	// Full indicates if the full topology is requested. This requires that this host
	// is on the ACL of the contacted DS server.
	Full bool
}

// Run fetches a new topology file from the discovery service and calls the
// appropriate callback functions to notify the caller. RawF and UpdateF are
// only called if no error has occurred and the topology was parsed correctly.
// Otherwise ErrorF is called.
func (f *Fetcher) Run(ctx context.Context) {
	if err := f.run(ctx); err != nil {
		f.callErrorF(err)
	}
}

func (f *Fetcher) run(ctx context.Context) error {
	// Choose a DS server.
	ds, err := f.Pool.Choose()
	if err != nil {
		return err
	}
	topo, raw, err := TopoRaw(ctx, f.Client, URL(ds.addr, f.Dynamic, f.Full, f.Https))
	if err != nil {
		ds.Fail()
		return err
	}
	// Update DS server entries based on new topo.
	if err := f.Pool.Update(topo); err != nil {
		return common.NewBasicError("Unable to update pool", err)
	}
	// Notify the client.
	f.callRawF(raw)
	f.callUpdateF(topo)
	return nil
}

func (f *Fetcher) callRawF(raw common.RawBytes) {
	if f.RawF != nil {
		f.RawF(raw)
	}
}

func (f *Fetcher) callUpdateF(topo *topology.Topo) {
	if f.UpdateF != nil {
		f.UpdateF(topo)
	}
}

func (f *Fetcher) callErrorF(err error) {
	if f.ErrorF != nil {
		f.ErrorF(err)
	}
}
