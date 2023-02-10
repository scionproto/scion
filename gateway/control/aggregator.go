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
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/worker"
)

const (
	defaultExpiryInterval    = 10 * time.Minute
	defaultReportingInterval = 10 * time.Second
)

// RemoteGateways defines the current discovered routing state.
type RemoteGateways struct {
	Gateways map[addr.IA][]RemoteGateway
}

// RemoteGateway is an entry for a single remote gateway.
type RemoteGateway struct {
	// Gateway contains the gateway specific information.
	Gateway Gateway
	// Prefixes is the list of prefixes served by this gateway.
	Prefixes []*net.IPNet
}

type gatewayEntry struct {
	IA          addr.IA
	Gateway     Gateway
	Prefixes    []*net.IPNet
	LastUpdated time.Time
}

// Aggregator aggregates prefix announcements and pushes the aggregated
// structure to the supplied channel.
type Aggregator struct {
	// RoutingUpdateChan is the channel that the routing updates will be pushed to.
	RoutingUpdateChan chan (RemoteGateways)
	// ReportingInterval is the interval between producing the reports. If there
	// are no changes, the actual interval may be longer.
	ReportingInterval time.Duration
	// ExpiryInterval means for how long will a gateway instance be reported if it
	// is not renewed.
	ExpiryInterval time.Duration

	mutex    sync.Mutex
	gateways map[string]gatewayEntry
	changed  bool

	workerBase worker.Base
}

// Run starts the aggregator. It must only be called once.
func (a *Aggregator) Run(ctx context.Context) error {
	return a.workerBase.RunWrapper(ctx, a.setup, a.run)
}

func (a *Aggregator) setup(ctx context.Context) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.ReportingInterval == 0 {
		a.ReportingInterval = defaultReportingInterval
	}
	if a.ExpiryInterval == 0 {
		a.ExpiryInterval = defaultExpiryInterval
	}
	if a.gateways == nil {
		a.gateways = make(map[string]gatewayEntry)
	}

	return nil
}

func (a *Aggregator) run(ctx context.Context) error {
	go func() {
		defer log.HandlePanic()
		ticker := time.NewTicker(a.ReportingInterval)
		for {
			select {
			case <-ticker.C:
				a.report()
			case <-a.workerBase.GetDoneChan():
				break
			}
		}
	}()
	return nil
}

// Close stops the internal goroutines.
func (a *Aggregator) Close(ctx context.Context) {
	_ = a.workerBase.CloseWrapper(ctx, nil)
}

// Prefixes pushes new set of prefixes for a specific gateway.
func (a *Aggregator) Prefixes(
	remote addr.IA,
	gateway Gateway,
	prefixes []*net.IPNet,
) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.gateways == nil {
		a.gateways = make(map[string]gatewayEntry)
	}
	key := fmt.Sprintf("%s/%s", remote.String(), gateway.Control.String())
	a.gateways[key] = gatewayEntry{
		IA:          remote,
		Gateway:     gateway,
		Prefixes:    prefixes,
		LastUpdated: time.Now(),
	}
	a.changed = true
	return nil
}

func (a *Aggregator) report() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Remove gateways from which we haven't heard for a while.
	now := time.Now()
	for key, entry := range a.gateways {
		if now.Sub(entry.LastUpdated) <= a.ExpiryInterval {
			continue
		}
		delete(a.gateways, key)
		a.changed = true
	}
	if !a.changed {
		return
	}
	// Push the prefixes to the consumer.
	ru := RemoteGateways{Gateways: make(map[addr.IA][]RemoteGateway)}
	keys := make([]string, 0)
	for key := range a.gateways {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := a.gateways[key]
		ru.Gateways[entry.IA] = append(ru.Gateways[entry.IA], RemoteGateway{
			Gateway:  entry.Gateway,
			Prefixes: entry.Prefixes,
		})
	}
	select {
	case a.RoutingUpdateChan <- ru:
		// Update written to the channel.
		a.changed = false
	default:
		// Update can't be written because the user is not consuming the
		// updates. Do nothing. We'll try again with the next tick.
	}
}
