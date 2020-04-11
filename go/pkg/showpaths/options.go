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

package showpaths

import (
	"net"

	"github.com/scionproto/scion/go/lib/sciond"
)

// DefaultMaxPaths is the maximum number of paths that are displayed by default.
const DefaultMaxPaths = 10

// Option configures the showpath run.
type Option func(*options)

type options struct {
	local      net.IP
	sciond     string
	maxPaths   int
	expiration bool
	refresh    bool
	probe      bool
}

func invokeOptions(opts []Option) options {
	o := options{
		sciond:   sciond.DefaultSCIONDAddress,
		maxPaths: DefaultMaxPaths,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// SCIOND configures a specific SCION Deamon address.
func SCIOND(sciond string) Option {
	return func(opts *options) { opts.sciond = sciond }
}

// MaxPaths configures the maximum number of displayed paths. If this option is
// not provided, the DefaultMaxPaths is used.
func MaxPaths(maxPaths int) Option {
	return func(opts *options) { opts.maxPaths = maxPaths }
}

// ShowExpiration configures whether the expiration is displayed.
func ShowExpiration(show bool) Option {
	return func(opts *options) { opts.expiration = show }
}

// Refresh configures whether sciond is queried with the refresh flag.
func Refresh(refresh bool) Option {
	return func(opts *options) { opts.refresh = refresh }

}

// Probe configures whether the path status is probed and displayed.
func Probe(probe bool) Option {
	return func(opts *options) { opts.probe = probe }

}

// Local configures the local IP address to use. If this option is not provided,
// a local IP that can reach SCION hosts is selected with the help of the kernel.
func Local(local net.IP) Option {
	return func(opts *options) { opts.local = local }
}
