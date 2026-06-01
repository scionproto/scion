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
	"path/filepath"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// AutoConnectorOption is a functional option for NewAutoConnector and
// overrides the default options.
type AutoConnectorOption func(*autoConnectorOptions)

type autoConnectorOptions struct {
	sciond    string
	configDir string
	metrics   Metrics
}

// WithDaemon sets the daemon address for a gRPC connector.
// When set, the connector will connect to the specified daemon via gRPC.
// If both WithDaemon and WithConfigDir are set, WithDaemon takes priority.
func WithDaemon(addr string) AutoConnectorOption {
	return func(o *autoConnectorOptions) {
		o.sciond = addr
	}
}

// WithConfigDir sets the configuration directory for standalone mode.
// The directory should contain topology.json and a certs/ subdirectory.
// If both WithDaemon and WithConfigDir are set, WithDaemon takes priority.
func WithConfigDir(dir string) AutoConnectorOption {
	return func(o *autoConnectorOptions) {
		o.configDir = dir
	}
}

func AutoWithMetrics(metrics Metrics) AutoConnectorOption {
	return func(o *autoConnectorOptions) {
		o.metrics = metrics
	}
}

// NewAutoConnector creates a new Connector based on supplied options.
//
// Priority order:
//  1. If WithDaemon was supplied, return a gRPC connector to the specified daemon.
//  2. If WithConfigDir was supplied, use standalone mode with the specified directory.
//  3. Return error if neither option was provided.
//
// Note: In standalone mode, topology information is loaded once and never reloaded.
// For dynamic updates, use [NewStandaloneConnector] with a custom [LocalASInfo].
func NewAutoConnector(ctx context.Context, opts ...AutoConnectorOption) (Connector, error) {
	options := &autoConnectorOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Priority 1: Use provided daemon address
	if options.sciond != "" {
		if !isReachable(options.sciond, defaultConnectionTimeout) {
			return nil, serrors.New("daemon not reachable", "address", options.sciond)
		}
		ctx, cancel := context.WithTimeout(ctx, defaultConnectionTimeout)
		defer cancel()
		return NewService(options.sciond, options.metrics).Connect(ctx)
	}

	// Priority 2: Use provided config directory for standalone mode
	if options.configDir != "" {
		topoFile := filepath.Join(options.configDir, "topology.json")
		certsDir := filepath.Join(options.configDir, "certs")
		localASInfo, err := LoadASInfoFromFile(topoFile)
		if err != nil {
			return nil, serrors.Wrap("loading topology from file", err,
				"topology_file", topoFile)
		}
		return NewStandaloneConnector(ctx, localASInfo, WithCertsDir(certsDir))
	}

	// TODO(emairoll): Include bootstrapping functionality

	return nil, serrors.New(
		"no suitable daemon connection method found: " +
			"either WithDaemon or WithConfigDir must be specified",
	)
}

func isReachable(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
