// Copyright 2020 Anapaya Systems
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

package trust

import (
	"context"
	"crypto/x509"
	"net"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
)

// Provider provides crypto material. A crypto provider can spawn network
// requests if necessary and permitted.
type Provider interface {
	// NotifyTRC notifies a provider of the existence of a TRC. When a signature
	// metadata is received that contains base and serial number, this method
	// should be invoked.
	NotifyTRC(context.Context, cppki.TRCID, ...Option) error
	// GetChains returns certificate chains that match the chain query. If no
	// chain is locally available, the provider can resolve them over the
	// network. By default, the provider only returns certificate chains that
	// are verifiable with the currently active TRCs. To configure the behavior,
	// options can be provided.
	GetChains(context.Context, ChainQuery, ...Option) ([][]*x509.Certificate, error)
	// GetSignedTRC returns the TRC with the given ID. If the TRC is not
	// available, the provider can resolve it over the network.
	GetSignedTRC(context.Context, cppki.TRCID, ...Option) (cppki.SignedTRC, error)
}

type options struct {
	allowInactive bool
	client        net.Addr
	server        net.Addr
}

func applyOptions(opts []Option) options {
	o := options{}
	for _, option := range opts {
		option(&o)
	}
	return o
}

// Option is a function that sets an option.
type Option func(o *options)

// AllowInactive allows chains that are verifiable with TRCs that are no longer
// active.
func AllowInactive() Option {
	return func(o *options) {
		o.allowInactive = true
	}
}

// Client sets the client that spawned the query. This lets the provider decide
// whether recursive resolution is allowed.
func Client(client net.Addr) Option {
	return func(o *options) {
		o.client = client
	}
}

// Server sets the server that should be queried in case of a crypto material
// resolution.
func Server(server net.Addr) Option {
	return func(o *options) {
		o.server = server
	}
}
