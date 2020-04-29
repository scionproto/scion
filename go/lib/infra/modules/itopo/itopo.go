// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package itopo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/scionproto/scion/go/lib/infra/modules/itopo/internal/metrics"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var st *state

// Callbacks are callbacks to respond to specific topology update events.
type Callbacks struct {
	// OnUpdate is called whenever the pointer to static topology is updated.
	OnUpdate func()
}

// providerFunc wraps the Get call as a topology provider.
type providerFunc func() topology.Topology

// Provider returns a topology provider that calls Get internally.
func Provider() topology.Provider {
	st.RLock()
	defer st.RUnlock()
	if st.topo.static == nil {
		panic("static topology not found")
	}
	return providerFunc(Get)
}

func (f providerFunc) Get() topology.Topology {
	return f()
}

// Config is used to initialize the package.
type Config struct {
	// ID is the application identifier.
	ID string
	// Svc is the service type of the application. Updated are treated differently depending
	// on it.
	Svc proto.ServiceType
	// Callbacks can be used to run custom code on specific events.
	Callbacks Callbacks
	// TopologyFactory is used to build Topology facades for the underlying topology object.
	// If nil, topology.FromRWTopology is used.
	TopologyFactory func(*topology.RWTopology) topology.Topology
}

// Init initializes the itopo package. A topology must be initialized by calling Update.
func Init(cfg *Config) {
	if st != nil {
		panic("Must not re-initialize itopo")
	}
	st = newState(cfg)
}

// Get atomically gets the pointer to the current topology.
func Get() topology.Topology {
	st.RLock()
	defer st.RUnlock()
	return runFactory(st.topo.Get())
}

// Update atomically sets the topology.
func Update(static topology.Topology) error {
	l := metrics.UpdateLabels{Type: metrics.Static}
	_, updated, err := st.setStatic(static.Writable())
	switch {
	case err != nil:
		l.Result = metrics.ErrValidate
	case updated:
		l.Result = metrics.Success
	default:
		l.Result = metrics.OkIgnored
	}
	incUpdateMetric(l)
	return err
}

// BeginUpdate checks whether setting the static topology is permissible. The returned
// transaction provides a view on which topology would be active, if committed.
func BeginUpdate(static *topology.RWTopology) (Transaction, error) {
	tx, err := st.beginUpdate(static)
	if err != nil {
		incUpdateMetric(metrics.UpdateLabels{Type: metrics.Static, Result: metrics.ErrValidate})
	}
	return tx, err
}

// Transaction allows to get a view on which topology will be active without committing
// to the topology update yet.
type Transaction struct {
	// candidateTopo contains the view of what the topology will be when the transaction is
	// successfully committed.
	candidateTopo topo
	// staticAtTxStart stores a snapshot of the currently active static
	// topology at transaction start.
	staticAtTxStart *topology.RWTopology
	// inputStatic stores the provided static topology.
	inputStatic *topology.RWTopology
}

// Commit commits the change. An error is returned, if the static topology changed in the meantime.
func (tx *Transaction) Commit() error {
	st.Lock()
	defer st.Unlock()
	l := metrics.UpdateLabels{Type: metrics.Dynamic}
	if tx.inputStatic != nil {
		l.Type = metrics.Static
	}
	if tx.staticAtTxStart != st.topo.static {
		incUpdateMetric(l.WithResult(metrics.ErrCommit))
		return serrors.New("Static topology changed in the meantime")
	}
	if !tx.IsUpdate() {
		incUpdateMetric(l.WithResult(metrics.OkIgnored))
		return nil
	}
	// Do transaction for static topology updated.
	if tx.inputStatic != nil {
		st.updateStatic(tx.inputStatic)
		incUpdateMetric(l.WithResult(metrics.Success))
		return nil
	}
	incUpdateMetric(l.WithResult(metrics.Success))
	return nil
}

// Get returns the topology that will be active if the transaction is committed.
func (tx *Transaction) Get() topology.Topology {
	return runFactory(tx.candidateTopo.Get())
}

// IsUpdate indicates whether the transaction will cause an update.
func (tx *Transaction) IsUpdate() bool {
	return tx.candidateTopo.static == tx.inputStatic
}

// topo stores the currently active static and dynamic topologies.
type topo struct {
	static *topology.RWTopology
}

// Get returns the dynamic topology if it is set and has not expired. Otherwise,
// the static topology is returned.
func (t *topo) Get() *topology.RWTopology {
	return t.static
}

// state keeps track of the active topologies and enforces update rules.
type state struct {
	sync.RWMutex
	topo      topo
	validator validator
	config    *Config
}

func newState(cfg *Config) *state {
	return &state{
		validator: validatorFactory(cfg.ID, cfg.Svc),
		config:    cfg,
	}
}

// setStatic atomically sets the static topology.
func (s *state) setStatic(static *topology.RWTopology) (*topology.RWTopology, bool, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.validator.Validate(static, s.topo.static); err != nil {
		return nil, false, err
	}
	// Only update static topology if the new one is different or valid for longer.
	if keepOld(static, s.topo.static) {
		return s.topo.Get(), false, nil
	}
	s.updateStatic(static)
	return s.topo.Get(), true, nil
}

func (s *state) beginUpdate(static *topology.RWTopology) (Transaction, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.validator.Validate(static, s.topo.static); err != nil {
		return Transaction{}, err
	}
	tx := Transaction{
		candidateTopo:   s.topo,
		staticAtTxStart: s.topo.static,
		inputStatic:     static,
	}
	if keepOld(tx.inputStatic, tx.staticAtTxStart) {
		return tx, nil
	}
	tx.candidateTopo.static = static
	return tx, nil
}

// updateStatic updates the static topology, if necessary, and calls the corresponding callbacks.
func (s *state) updateStatic(static *topology.RWTopology) {
	s.topo.static = static
	call(s.config.Callbacks.OnUpdate)
	cl := metrics.CurrentLabels{Type: metrics.Static}
	metrics.Current.Timestamp(cl).Set(metrics.Timestamp(static.Timestamp))
}

func keepOld(newTopo, oldTopo *topology.RWTopology) bool {
	return topoEq(newTopo, oldTopo) && !expiresLater(newTopo, oldTopo)
}

func topoEq(newTopo, oldTopo *topology.RWTopology) bool {
	return cmp.Equal(newTopo, oldTopo, cmpopts.IgnoreFields(
		topology.RWTopology{}, "Timestamp"))
}

func expiresLater(newTopo, oldTopo *topology.RWTopology) bool {
	if oldTopo == nil {
		return true
	}
	newTS := newTopo.Timestamp
	oldTS := oldTopo.Timestamp
	return !oldTS.IsZero() && (newTS.IsZero() || newTS.After(oldTS))
}

func call(clbk func()) {
	if clbk != nil {
		go func() {
			defer log.HandlePanic()
			clbk()
		}()
	}
}

func incUpdateMetric(l metrics.UpdateLabels) {
	metrics.Updates.Last(l).SetToCurrentTime()
	metrics.Updates.Total(l).Inc()
}

func TopologyHandler(w http.ResponseWriter, r *http.Request) {
	st.RLock()
	defer st.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	bytes, err := json.MarshalIndent(st.topo.Get(), "", "    ")
	if err == nil {
		fmt.Fprint(w, string(bytes)+"\n")
	}
}

func runFactory(topo *topology.RWTopology) topology.Topology {
	if st.config.TopologyFactory != nil {
		return st.config.TopologyFactory(topo)
	}
	return topology.FromRWTopology(topo)
}
