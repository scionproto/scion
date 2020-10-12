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
	"os"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/router/brconf"
	"github.com/scionproto/scion/go/pkg/router/svchealth"
)

const (
	svcHealthDiscoveryInterval = time.Second
	svcHealthDiscoveryTimeout  = 500 * time.Millisecond
)

// IACtx is the context for the router for a given IA.
type IACtx struct {
	// BRConf is the router topology configuration
	BRConf *brconf.BRConf
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
	brConf := iac.BRConf
	if brConf == nil {
		// Nothing to do
		return serrors.New("empty configuration")
	}

	log.Debug("Configuring Dataplane")
	if err := ConfigDataplane(iac.DP, brConf); err != nil {
		brConfDump, errDump := dumpConfig(brConf)
		if errDump != nil {
			brConfDump = serrors.FmtError(errDump)
		}
		return serrors.WrapStr("config setup", err, "config", brConfDump)
	}
	log.Debug("Dataplane configured successfully", "config", brConf)

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
		Topology:   iac.BRConf.Topo,
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
						if err := iac.DP.AddSvc(iac.BRConf.IA, svc, ip); err != nil {
							logger.Info("Failed to set service", "svc", svc, "ip", ip, "err", err)
						}
					}
					remove := diff.Remove[svc]
					for _, ip := range remove {
						if err := iac.DP.DelSvc(iac.BRConf.IA, svc, ip); err != nil {
							logger.Info("Failed to delete service",
								"svc", svc, "ip", ip, "err", err)
						}
					}
				}
			},
		}, svcHealthDiscoveryInterval, svcHealthDiscoveryTimeout)
	return nil
}

func dumpConfig(brConf *brconf.BRConf) (string, error) {
	if brConf == nil {
		return "", serrors.New("empty configuration")
	}
	b, err := json.MarshalIndent(brConf, "", "    ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
