// Copyright 2025 ETH Zurich
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

package daemon

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// SuppliedOption is a functional option for DefaultConnector and overrides the default priorities.
type SuppliedOption func(*suppliedOptions)

type suppliedOptions struct {
	sciond string
}

// WithDaemon sets the daemon address for a gRPC connector.
// This has the lowest priority.
func WithDaemon(addr string) SuppliedOption {
	return func(o *suppliedOptions) {
		o.sciond = addr
	}
}

// DefaultConnector creates a new Connector based on supplied and default options.
//
// Priority order of supplied options:
//  1. If WithDaemon was called, return a gRPC connector to the specified daemon.
//
// Priority order of default options:
//  1. Load topology from file if it exists.
//  2. Connect to daemon via gRPC if reachable.
//  3. Return error if none of the above are successful.
//
// TODO: include bootstrapping functionality
func DefaultConnector(ctx context.Context, opts ...SuppliedOption) (Connector, error) {
	options := &suppliedOptions{}
	for _, opt := range opts {
		opt(options)
	}
	// SUPPLIED OPTIONS
	// Priority 1: Use provided daemon address
	if options.sciond != "" {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return NewService(options.sciond).Connect(ctx)
	}

	// DEFAULT FALLBACKS
	// Priority 1: Load topology from file if it exists
	if _, err := os.Stat(DefaultTopologyFile); err == nil {
		topo, err := LoadTopologyFromFile(DefaultTopologyFile)
		if err != nil {
			return nil, serrors.Wrap("loading topology from file", err)
		}
		return NewStandaloneConnector(ctx, topo, WithCertsDir(DefaultCertsDir))
	}

	// Priority 2: Connect to daemon via gRPC
	if isReachable(DefaultAPIAddress, 500*time.Millisecond) {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return NewService(DefaultAPIAddress).Connect(ctx)
	}

	// TODO: Better error message
	return nil, serrors.New(
		"no suitable daemon connection method found",
		"tried_supplied_api_address", options.sciond,
		"tried_default_topology_file", DefaultTopologyFile,
		"tried_default_api_address", DefaultAPIAddress,
	)
}

func isReachable(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
