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

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/router/svchealth"
)

const (
	svcHealthDiscoveryInterval = time.Second
	svcHealthDiscoveryTimeout  = 500 * time.Millisecond
)

// Config stores the runtime configuration state of an ISD-AS context.
type Config struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo topology.Topology
	// IA is the current ISD-AS.
	IA addr.IA
	// BR is the topology information of this router.
	BR *topology.BRInfo
	// MasterKeys holds the local AS master keys.
	MasterKeys keyconf.Master
}

// LoadConfig sets up the configuration, loading it from the supplied config directory.
func LoadConfig(id, confDir string) (*Config, error) {
	conf := &Config{}
	if err := conf.loadTopo(id, confDir); err != nil {
		return nil, err
	}
	if err := conf.loadMasterKeys(confDir); err != nil {
		return nil, err
	}
	return conf, nil
}

func (cfg *Config) String() string {
	return fmt.Sprintf("{IA: %s, BR.Name: %s", cfg.IA, cfg.BR.Name)
}

// loadTopo loads the topology from the config directory and initializes the
// entries related to topo in the config.
func (cfg *Config) loadTopo(id string, confDir string) error {
	topoPath := filepath.Join(confDir, "topology.json")
	topo, err := topology.FromJSONFile(topoPath)
	if err != nil {
		return err
	}
	if err := cfg.initTopo(id, topo); err != nil {
		return serrors.WrapStr("initializing topology", err, "file", topoPath)
	}
	return nil
}

// initTopo initializes the entries related to topo in the config.
func (cfg *Config) initTopo(id string, topo topology.Topology) error {
	cfg.Topo = topo
	cfg.IA = cfg.Topo.IA()
	// Find the config for this router.
	topoBR, ok := cfg.Topo.BR(id)
	if !ok {
		return serrors.New("element ID not found", "id", id)
	}
	cfg.BR = &topoBR
	return nil
}

// loadMasterKeys loads the master keys from the config directory.
func (cfg *Config) loadMasterKeys(confDir string) error {
	var err error
	cfg.MasterKeys, err = keyconf.LoadMaster(filepath.Join(confDir, "keys"))
	if err != nil {
		return serrors.WrapStr("loading master keys", err)
	}
	return nil
}

// IACtx is the context for the router for a given IA.
type IACtx struct {
	// Config is the router topology configuration
	Config *Config
	// DP is the underlying data plane.
	DP Dataplane
	// Discoverer is used to dynamically discover healthy service instances. If
	// nil, service health watching is disabled.
	Discoverer svchealth.Discoverer
	// Stop channel, used for ISD-AS context cleanup
	Stop chan struct{}

	// svcHealthWatcher watches for service health changes.
	svcHealthWatcher *periodic.Runner
}

// Start configures the dataplane for the given context.
func (iac *IACtx) Start(wg *sync.WaitGroup) error {
	cfg := iac.Config
	if cfg == nil {
		// Nothing to do
		return serrors.New("empty configuration")
	}

	log.Debug("Configuring Dataplane")
	if err := ConfigDataplane(iac.DP, cfg); err != nil {
		brConfDump, errDump := dumpConfig(cfg)
		if errDump != nil {
			brConfDump = serrors.FmtError(errDump)
		}
		return serrors.WrapStr("config setup", err, "config", brConfDump)
	}
	log.Debug("Dataplane configured successfully", "config", cfg)

	_, disableSvcHealth := os.LookupEnv("SCION_EXPERIMENTAL_DISABLE_SERVICE_HEALTH")
	if !disableSvcHealth && iac.Discoverer != nil {
		if err := iac.watchSVCHealth(); err != nil {
			return serrors.WrapStr("starting service health watcher", err)
		}
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			<-iac.Stop
			iac.svcHealthWatcher.Kill()
		}()
	}
	return nil
}

func (iac *IACtx) watchSVCHealth() error {
	w := svchealth.Watcher{
		Discoverer: iac.Discoverer,
		Topology:   iac.Config.Topo,
	}
	iac.svcHealthWatcher = periodic.Start(
		periodic.Func{
			TaskName: "svchealth.Watcher",
			Task: func(ctx context.Context) {
				logger := log.FromCtx(ctx)

				diff, err := w.Discover(ctx)
				if err != nil {
					logger.Info("Ignoring service health update", "err", err)
					return
				}
				for _, svc := range []addr.HostSVC{addr.SvcDS, addr.SvcCS} {
					add := diff.Add[svc]
					for _, ip := range add {
						if err := iac.DP.AddSvc(iac.Config.IA, svc, ip); err != nil {
							logger.Info("Failed to set service", "svc", svc, "ip", ip, "err", err)
						}
					}
					remove := diff.Remove[svc]
					for _, ip := range remove {
						if err := iac.DP.DelSvc(iac.Config.IA, svc, ip); err != nil {
							logger.Info("Failed to delete service",
								"svc", svc, "ip", ip, "err", err)
						}
					}
				}
			},
		}, svcHealthDiscoveryInterval, svcHealthDiscoveryTimeout)
	return nil
}

func dumpConfig(cfg *Config) (string, error) {
	if cfg == nil {
		return "", serrors.New("empty configuration")
	}
	b, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
