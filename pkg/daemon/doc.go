// Copyright 2026 ETH Zurich
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

/*
Package daemon provides APIs for SCION applications to interact with the
SCION control plane. It supports two modes of operation:

  - Standalone mode: Runs daemon functionality in-process, communicating
    directly with the control service. No separate daemon process required.
  - Remote mode: Connects to a SCION daemon process via gRPC.

# Quick Start

Use NewAutoConnector with WithDaemon (for remote daemon) or WithConfigDir
(for standalone mode):

	// Remote daemon connection
	conn, err := daemon.NewAutoConnector(ctx, daemon.WithDaemon("127.0.0.1:30255"))

	// Or standalone mode with local config
	conn, err := daemon.NewAutoConnector(ctx, daemon.WithConfigDir("/etc/scion"))

	if err != nil {
	    log.Fatal(err)
	}
	defer conn.Close()

	// Query paths to a destination
	paths, err := conn.Paths(ctx, dstIA, srcIA, daemon.PathReqFlags{})

If both WithDaemon and WithConfigDir are set, WithDaemon takes priority.
Empty string options are ignored, making it safe to pass values from CLI flags:

	conn, err := daemon.NewAutoConnector(ctx,
	    daemon.WithDaemon(daemonAddr),    // may be empty
	    daemon.WithConfigDir(configDir),  // may be empty
	)

# Standalone Mode

Standalone mode runs the daemon logic in-process, which is useful for:
  - Deployments without a separate daemon process
  - CLI tools that need minimal dependencies
  - Testing and development

For more control over standalone mode, use NewStandaloneConnector directly:

	// Load topology information
	localASInfo, err := daemon.LoadASInfoFromFile("/etc/scion/topology.json")
	if err != nil {
	    log.Fatal(err)
	}

	// Create standalone connector with options
	conn, err := daemon.NewStandaloneConnector(ctx, localASInfo,
	    daemon.WithCertsDir("/etc/scion/certs"),     // TRC certificates location
	    daemon.WithMetrics(),                         // Enable Prometheus metrics
	    daemon.WithPeriodicCleanup(),                 // Enable path DB cleanup
	)
	if err != nil {
	    log.Fatal(err)
	}
	defer conn.Close()

Standalone mode requires:
  - topology.json: Network topology file with control service addresses
  - certs/: Directory containing TRC files for segment verification (required via WithCertsDir)

To disable segment verification (NOT recommended for production):

	conn, err := daemon.NewStandaloneConnector(ctx, localASInfo,
	    daemon.WithDisabledSegVerification(),
	)

# Remote Mode

Remote mode connects to a running SCION daemon via gRPC. Use NewService to
create a connection factory:

	svc := daemon.NewService("127.0.0.1:30255")
	conn, err := svc.Connect(ctx)
	if err != nil {
	    log.Fatal(err)
	}
	defer conn.Close()

# The Connector Interface

The Connector interface is the central abstraction of this package. All connection
modes (standalone, remote) implement this interface, allowing applications to work
with any backend transparently.

See [Connector] for all available methods.

# Loading Topology

To get topology information (local IA, port range, interfaces) from a connector:

	// One-time load
	topo, err := daemon.LoadTopology(ctx, conn)

	// Auto-reloading topology (for long-running applications)
	reloadingTopo, err := daemon.NewReloadingTopology(ctx, conn)
	go reloadingTopo.Run(ctx, 30*time.Second)
	topo := reloadingTopo.Topology()

# Helper Types

The package provides helper types for common patterns:

	// Querier wraps a Connector for path queries
	querier := daemon.Querier{Connector: conn, IA: localIA}
	paths, err := querier.Query(ctx, dstIA)

	// RevHandler adapts Connector for snet.RevocationHandler
	revHandler := daemon.RevHandler{Connector: conn}

	// TopoQuerier provides topology queries
	topoQuerier := daemon.TopoQuerier{Connector: conn}
	addr, err := topoQuerier.UnderlayAnycast(ctx, addr.SvcCS)
*/
package daemon
