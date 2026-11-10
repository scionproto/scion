// Copyright 2026 Anapaya Systems
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

// Package system_test tests IP connectivity through SCION IP gateways in a
// containerlab topology.
//
// testgen --gateways runs a gateway on host-1 of every AS. Each gateway owns
// an IPv4 prefix and holds the first address of it on the host's loopback
// interface. The gateways route the prefixes of all other ASes through their
// tunnel. The test pings from every gateway host to every other one, from and
// to the addresses in the gateway prefixes, so every ping crosses two
// gateways and the SCION network between them.
//
// The test runs once per RPC protocol combination of the control services and
// gateways, to check the gRPC/connectrpc transition. All combinations run
// against the same lab: before each one, the test rewrites the [rpc] section
// of the service configurations and restarts the services through the node
// controller.
package system_test

import (
	"cmp"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/testing/clab"
	"github.com/scionproto/scion/testing/clab/e2e"
	"github.com/scionproto/scion/testing/clab/testgen/hydrate"
)

var (
	phased = clab.RegisterPhasedTest()

	topoFile = flag.String("topo", clab.EnvOr("CLAB_TOPO", "topology/tiny4.topo"),
		"testgen topology description file",
	)
	pingCount = flag.Int("ping-count", 5, "number of pings per gateway pair")
	readyTO   = flag.Duration("ready-timeout", time.Minute,
		"how long to wait for the gateway tunnels to come up",
	)
)

const (
	labName = "gateway"
	// configDir is where the node controller writes the service configs.
	configDir = "/etc/scion"
	// controller is the node controller binary in the node image.
	controller    = "/app/controller"
	dockerTimeout = time.Minute
)

// rpcVariant is a combination of RPC protocols for the control services and
// the gateways.
type rpcVariant struct {
	name   string
	client string
	server string
}

var rpcVariants = []rpcVariant{
	// Clients and servers speak both protocols; connectrpc is preferred.
	{name: "all", client: "all", server: "all"},
	// Old, gRPC-only clients can talk to transition (bi-compatible) servers.
	{name: "grpc_client", client: "grpc", server: "all"},
	// Transition (bi-compatible) clients can talk to old gRPC-only servers.
	{name: "grpc_server", client: "all", server: "grpc"},
	// Clients and servers still talk after gRPC is removed from both sides.
	{name: "connectrpc", client: "connectrpc", server: "connectrpc"},
}

func TestGateway(t *testing.T) {
	env := clab.NewEnvironment(t, phased, labName)
	// Register the teardown first, so that it runs last, even if the test
	// fails.
	phased.TeardownCleanup(t, func() { env.Destroy(t) })

	if phased.Setup() {
		env.Deploy(t, *topoFile, "--gateways")
	}
	if !phased.Execute() {
		return
	}

	l := loadLab(t, env)
	for _, v := range rpcVariants {
		t.Run(v.name, func(t *testing.T) {
			l.configureRPC(t, v)
			l.awaitTunnels(t)
			l.pingAll(t, v)
		})
	}
}

// lab is the deployed topology, as far as the test is concerned.
type lab struct {
	env *clab.Environment
	// gateways are the gateway hosts, sorted by ISD-AS.
	gateways []gateway
	// services are the services whose RPC protocols the test configures.
	services []service
}

// gateway is a gateway host. Its address in the gateway prefix is the source
// and destination of the pings.
type gateway struct {
	ia        addr.IA
	container string
	addr      string
}

// service is a SCION service on a node. Its ID is the service name in the
// node controller, and the stem of its configuration file.
type service struct {
	container string
	id        string
}

func (s service) config() string {
	return configDir + "/" + s.id + ".toml"
}

// loadLab reads the gateways and the control services from the allocation
// record that testgen wrote.
func loadLab(t *testing.T, env *clab.Environment) *lab {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(env.GenDir, "network-allocations.yml"))
	require.NoError(t, err)
	var allocs hydrate.Allocations
	require.NoError(t, yaml.Unmarshal(raw, &allocs))
	require.NotEmpty(t, allocs.Gateways, "no gateways in the lab; generated without --gateways?")

	l := &lab{env: env}
	gatewayIDs := map[string]bool{}
	for _, g := range allocs.Gateways {
		ia, err := addr.ParseIA(g.ISDAS)
		require.NoError(t, err)
		l.gateways = append(l.gateways, gateway{
			ia:        ia,
			container: env.Container(ia, g.Host),
			addr:      g.Addr,
		})
		gatewayIDs[g.ID] = true
	}
	require.GreaterOrEqual(t, len(l.gateways), 2, "need at least two gateways")
	slices.SortFunc(l.gateways, func(a, b gateway) int { return cmp.Compare(a.ia, b.ia) })

	for _, as := range allocs.ASes {
		ia, err := addr.ParseIA(as.ISDAS)
		require.NoError(t, err)
		for _, h := range as.Hosts {
			for _, id := range h.Elements {
				if gatewayIDs[id] || strings.HasPrefix(id, "cs") {
					l.services = append(l.services, service{
						container: env.Container(ia, h.Name),
						id:        id,
					})
				}
			}
		}
	}
	return l
}

// configureRPC sets the RPC protocols of all control services and gateways
// and restarts them. The containers are configured in parallel. It waits until
// the control services re-established full connectivity.
func (l *lab) configureRPC(t *testing.T, v rpcVariant) {
	t.Helper()
	t.Logf("--- configuring RPC protocols: client %s, server %s", v.client, v.server)
	byContainer := map[string][]service{}
	var containers []string
	for _, s := range l.services {
		if _, ok := byContainer[s.container]; !ok {
			containers = append(containers, s.container)
		}
		byContainer[s.container] = append(byContainer[s.container], s)
	}
	errs := make([]error, len(containers))
	var wg sync.WaitGroup
	for i, c := range containers {
		wg.Go(func() { errs[i] = l.configureContainer(c, byContainer[c], v) })
	}
	wg.Wait()
	for i, c := range containers {
		require.NoError(t, errs[i], "configuring %s", c)
		t.Logf("restarted %v in %s", serviceIDs(byContainer[c]), c)
	}
	l.env.AwaitConnectivity(t)
}

// configureContainer rewrites the [rpc] section of the configurations of the
// services in one container, and then restarts the services. The node
// controller returns once they run again with the new configuration.
func (l *lab) configureContainer(container string, services []service, v rpcVariant) error {
	for _, s := range services {
		cfg, err := l.readConfig(s)
		if err != nil {
			return err
		}
		cfg["rpc"] = map[string]any{
			"client_protocol": v.client,
			"server_protocol": v.server,
		}
		if err := l.writeConfig(s, cfg); err != nil {
			return err
		}
	}
	args := append([]string{"exec", container, controller, "services", "restart"},
		serviceIDs(services)...)
	if out, err := l.env.Docker(dockerTimeout, args...); err != nil {
		return fmt.Errorf("restarting %v: %w: %s", serviceIDs(services), err, out)
	}
	return nil
}

func serviceIDs(services []service) []string {
	ids := make([]string, 0, len(services))
	for _, s := range services {
		ids = append(ids, s.id)
	}
	return ids
}

func (l *lab) readConfig(s service) (map[string]any, error) {
	out, err := l.env.Docker(dockerTimeout, "exec", s.container, "cat", s.config())
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w: %s", s.config(), err, out)
	}
	var cfg map[string]any
	if err := toml.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.config(), err)
	}
	return cfg, nil
}

func (l *lab) writeConfig(s service, cfg map[string]any) error {
	raw, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	// Pass the content base64-encoded, so that it needs no shell quoting.
	script := fmt.Sprintf("echo %s | base64 -d > %s",
		base64.StdEncoding.EncodeToString(raw), s.config())
	out, err := l.env.Docker(dockerTimeout, "exec", s.container, "sh", "-c", script)
	if err != nil {
		return fmt.Errorf("writing %s: %w: %s", s.config(), err, out)
	}
	return nil
}

// awaitTunnels waits until a single ping succeeds between every pair of
// gateway hosts. The gateways need a moment after a restart to discover the
// remote gateways and set up their sessions. The pairs are probed in
// parallel.
func (l *lab) awaitTunnels(t *testing.T) {
	t.Helper()
	t.Log("--- waiting for the gateway tunnels")
	deadline := time.Now().Add(*readyTO)
	pending := l.pairs()
	for {
		ok := make([]bool, len(pending))
		var wg sync.WaitGroup
		for i, p := range pending {
			wg.Go(func() {
				_, err := l.ping(p[0], p[1], 1)
				ok[i] = err == nil
			})
		}
		wg.Wait()
		var still [][2]gateway
		for i, p := range pending {
			if !ok[i] {
				still = append(still, p)
			}
		}
		pending = still
		if len(pending) == 0 {
			return
		}
		if time.Now().After(deadline) {
			var missing []string
			for _, p := range pending {
				missing = append(missing, fmt.Sprintf("%s -> %s", p[0].ia, p[1].ia))
			}
			require.Failf(t, "gateway tunnels not ready",
				"no ping got through within %s: %s", *readyTO, strings.Join(missing, ", "))
		}
		time.Sleep(time.Second)
	}
}

// pingAll pings between every pair of gateway hosts, prints the result
// matrix, and fails the test if any pair fails.
func (l *lab) pingAll(t *testing.T, v rpcVariant) {
	t.Helper()
	type result struct {
		out string
		err error
	}
	pairs := l.pairs()
	results := make([]result, len(pairs))
	var wg sync.WaitGroup
	for i, p := range pairs {
		wg.Go(func() {
			out, err := l.ping(p[0], p[1], *pingCount)
			results[i] = result{out: out, err: err}
		})
	}
	wg.Wait()

	byPair := map[[2]addr.IA]result{}
	failed := 0
	for i, p := range pairs {
		byPair[[2]addr.IA{p[0].ia, p[1].ia}] = results[i]
		if results[i].err != nil {
			failed++
		}
	}

	var report strings.Builder
	fmt.Fprintf(&report, "ping: %d/%d ok\n", len(pairs)-failed, len(pairs))
	eps := make([]e2e.Endpoint, 0, len(l.gateways))
	for _, g := range l.gateways {
		eps = append(eps, endpoint(g))
	}
	e2e.FprintMatrix(&report, eps, func(src, dst e2e.Endpoint) bool {
		return byPair[[2]addr.IA{
			addr.MustParseIA(src.IA), addr.MustParseIA(dst.IA),
		}].err == nil
	})
	// The pairs are in order, so the failures are sorted by source and
	// destination.
	for i, p := range pairs {
		if r := results[i]; r.err != nil {
			fmt.Fprintf(&report, "%s -> %s: %v\n%s\n", p[0].ia, p[1].ia, r.err, r.out)
		}
	}
	t.Log("\n" + report.String())
	l.env.Collect(t, []byte(report.String()), "gateway_ping_"+v.name+".log")
	require.Zero(t, failed, "pings through the gateways failed")
}

// ping pings from the gateway host src to the gateway host dst, from and to
// their addresses in the gateway prefixes. It succeeds if at least one reply
// arrives.
func (l *lab) ping(src, dst gateway, count int) (string, error) {
	out, err := l.env.Docker(dockerTimeout, "exec", src.container,
		"ping", "-c", fmt.Sprint(count), "-i", "0.2", "-W", "2", "-I", src.addr, dst.addr)
	return string(out), err
}

// pairs returns all ordered pairs of distinct gateways.
func (l *lab) pairs() [][2]gateway {
	var out [][2]gateway
	for _, src := range l.gateways {
		for _, dst := range l.gateways {
			if src.ia != dst.ia {
				out = append(out, [2]gateway{src, dst})
			}
		}
	}
	return out
}

func endpoint(g gateway) e2e.Endpoint {
	return e2e.Endpoint{IA: g.ia.String(), Container: g.container, Host: g.addr}
}
