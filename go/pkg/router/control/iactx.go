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
	"encoding/json"
	"os"
	"sync"

	"github.com/scionproto/scion/go/border/brconf"
	rctrlgrpc "github.com/scionproto/scion/go/border/rctrl/grpc"
	"github.com/scionproto/scion/go/lib/log"
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/router/control/internal/metrics"
)

// IACtx is the context for the router for a given IA.
type IACtx struct {
	// BRConf is the router topology configuration
	BRConf *brconf.BRConf
	// DP is the underlying data plane.
	DP Dataplane
	// Stop channel, used for ISD-AS context cleanup
	Stop chan struct{}
	// DisableLegacyIfStateMgmt indicates whether the legacy interface state
	// management should be disabled.
	DisableLegacyIfStateMgmt bool

	// Revocation expiration timers
	timers *revTimer
}

// Start configures the dataplane for the given context.
func (iac *IACtx) Start(wg *sync.WaitGroup, v2 bool) error {
	iac.timers = &revTimer{}

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

	_, disableUpdate := os.LookupEnv("SCION_ROUTER_DISABLE_IFSTATE_MGMT")
	disableUpdate = disableUpdate || iac.DisableLegacyIfStateMgmt
	if disableUpdate {
		log.Info("interface state mgmt disabled")
		return nil
	}

	wg.Add(2)

	// Start goroutine that processes control packets
	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		processCtrl(iac)
	}()
	// Start IFStateReq goroutine
	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		updater := rctrlgrpc.IfStateUpdater{
			Dialer:         grpc.SimpleDialer{},
			Handler:        StateHandler{c: iac},
			IfStateTicker:  libmetrics.NoWith(metrics.Control.IFStateTick()),
			SendCounter:    libmetrics.NewPromCounter(metrics.Control.SendIFStateReqVec()),
			ReceiveCounter: libmetrics.NewPromCounter(metrics.Control.ReceivedIFStateInfoVec()),
			ProcessErrors:  libmetrics.NewPromCounter(metrics.Control.ProcessErrorsVec()),
			Logger:         log.Root(),
		}
		ifStateReq(iac, updater)
	}()
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
