// Copyright 2021 Anapaya Systems
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

package topology

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
)

// Validator is used to validate that the topology update is permissible.
type Validator interface {
	// Validate checks that the topology update is valid. Note that old might be
	// nil.
	Validate(new, old *RWTopology) error
}

// LoaderMetrics are the metrics exposed by the topology loader. Individual
// values can be nil, which means they will not be exposed.
type LoaderMetrics struct {
	// ValidationErrors counts the amount of validation errors.
	ValidationErrors metrics.Counter
	// ReadErrors counts the amount of file read or parse errors.
	ReadErrors metrics.Counter
	// LastUpdate indicates the timestamp of the last successful update.
	LastUpdate metrics.Gauge
	// Updates counts the amount of successful updates.
	Updates metrics.Counter
}

// LoaderCfg is the configuration for the topology loader.
type LoaderCfg struct {
	// File is the file from which the topology should be loaded.
	File string
	// Reload is the channel on which reloads can be triggered.
	Reload <-chan struct{}
	// Validator is used to validate topology updates. If this field is not set,
	// update is permissible. If the validation is error a reload is discarded
	Validator Validator
	// Metrics are the metrics of the loader, if left empty no metrics are
	// reported.
	Metrics LoaderMetrics
}

// Loader can be used to reload the topology transparently. The default object
// is not usable and the loaded should be constructed with the NewLoader
// function.
type Loader struct {
	cfg LoaderCfg

	mtx         sync.Mutex
	subscribers map[*Subscription]chan struct{}
	topo        Topology
}

// NewLoader creates a topology loader from the given configuration. This method
// tries to load the file initially and if that doesn't succeeds an error is
// returned.
func NewLoader(cfg LoaderCfg) (*Loader, error) {
	l := &Loader{
		cfg:         cfg,
		subscribers: make(map[*Subscription]chan struct{}),
	}
	if err := l.reload(); err != nil {
		return nil, err
	}
	return l, nil
}

// Run runs the topology reloader. It makes sure that the topology is reloaded
// when the configured signal channel is filled. A topology that can't be parsed
// or doesn't validate will be ignored.
func (l *Loader) Run(ctx context.Context) error {
	for {
		select {
		case <-l.cfg.Reload:
			if err := l.reload(); err != nil {
				log.FromCtx(ctx).Error("Failed to reload topology file",
					"file", l.cfg.File, "err", err)
			} else {
				log.FromCtx(ctx).Info("Reloaded topology")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (l *Loader) IA() addr.IA {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.IA()
}

func (l *Loader) MTU() uint16 {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.MTU()
}

func (l *Loader) Core() bool {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.Core()
}

func (l *Loader) UnderlayNextHop(ifID uint16) *net.UDPAddr {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	addr, _ := l.topo.UnderlayNextHop(iface.ID(ifID))
	return addr
}

func (l *Loader) IfIDs() []uint16 {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	var ids []uint16
	for _, id := range l.topo.IfIDs() {
		ids = append(ids, uint16(id))
	}
	return ids
}

func (l *Loader) PortRange() (uint16, uint16) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.PortRange()
}

func (l *Loader) ControlServiceAddresses() []*net.UDPAddr {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	addrs, err := l.topo.MakeHostInfos(Control)
	if err != nil {
		// this should only happen on empty addrs.
		return nil
	}
	return addrs
}

func (l *Loader) ControlServiceAddress(id string) *net.UDPAddr {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.PublicAddress(addr.SvcCS, id)
}

// TODO(lukedirtwalker): remove error and simplify struct in the return type.
func (l *Loader) Gateways() ([]GatewayInfo, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.Gateways()
}

func (l *Loader) InterfaceInfoMap() map[iface.ID]IFInfo {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.IFInfoMap().copy()
}

// TODO(lukedirtwalker): remove error.
func (l *Loader) HiddenSegmentLookupAddresses() ([]*net.UDPAddr, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	a, err := l.topo.MakeHostInfos(HiddenSegmentLookup)
	if errors.Is(err, ErrAddressNotFound) {
		return nil, nil
	}
	return a, err
}

// TODO(lukedirtwalker): remove error.
func (l *Loader) HiddenSegmentRegistrationAddresses() ([]*net.UDPAddr, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	a, err := l.topo.MakeHostInfos(HiddenSegmentRegistration)
	if errors.Is(err, ErrAddressNotFound) {
		return nil, nil
	}
	return a, err
}

// TODO(lukedirtwalker): remove error / cleanup.
func (l *Loader) GetUnderlay(svc addr.SVC) (*net.UDPAddr, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo.UnderlayAnycast(svc)
}

// Get gets the instance of the topology.
//
// Deprecated: New code should use accessor methods instead.
func (l *Loader) Get() Topology {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.topo
}

func (l *Loader) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	bytes, err := json.MarshalIndent(l.Get().Writable(), "", "    ")
	if err == nil {
		fmt.Fprint(w, string(bytes)+"\n")
	}
}

// Subscription is a subscription for topology updates. It should be Closed
// whenever it's no longer used. When the context of the Loader is cancelled the
// Subscription will no longer be served, but the subscription channel is not
// closed. It is the user responsibility to stop using the Subscription if the
// Loader context is cancelled.
type Subscription struct {
	Updates <-chan struct{}

	unsubscribe func()
}

func (s *Subscription) Close() {
	s.unsubscribe()
}

// Subscribe can be used to subscribe to updates.
func (l *Loader) Subscribe() *Subscription {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	ch := make(chan struct{})
	sub := &Subscription{
		Updates: ch,
	}
	l.subscribers[sub] = ch
	sub.unsubscribe = func() {
		l.unsubscribe(sub)
	}
	return sub
}

func (l *Loader) unsubscribe(sub *Subscription) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	delete(l.subscribers, sub)
}

func (l *Loader) notifyAllLocked() {
	for _, v := range l.subscribers {
		v <- struct{}{}
	}
}

func (l *Loader) reload() error {
	newTopo, err := l.load()
	if err != nil {
		metrics.CounterInc(l.cfg.Metrics.ReadErrors)
		return serrors.Wrap("loading topology", err)
	}

	l.mtx.Lock()
	defer l.mtx.Unlock()

	var old *RWTopology
	if l.topo != nil {
		old = l.topo.Writable()
	}

	if err := l.validate(newTopo.Writable(), old); err != nil {
		metrics.CounterInc(l.cfg.Metrics.ValidationErrors)
		return serrors.Wrap("validating update", err)
	}
	l.topo = newTopo
	metrics.CounterInc(l.cfg.Metrics.Updates)
	metrics.GaugeSetCurrentTime(l.cfg.Metrics.LastUpdate)

	l.notifyAllLocked()
	return nil
}

func (l *Loader) load() (Topology, error) {
	topo, err := FromJSONFile(l.cfg.File)
	if err != nil {
		return nil, err
	}
	return topo, nil
}

func (l *Loader) validate(new, old *RWTopology) error {
	if l.cfg.Validator == nil {
		return nil
	}
	return l.cfg.Validator.Validate(new, old)
}
