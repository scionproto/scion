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
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var st *state

// Callbacks are callbacks to respond to specific topology update events.
type Callbacks struct {
	// CleanDynamic is called whenever dynamic topology is dropped due to expiration.
	CleanDynamic func()
	// DropDynamic is called whenever dynamic topology is dropped due to static update.
	DropDynamic func()
	// UpdateStatic is called whenever the pointer to static topology is updated.
	UpdateStatic func()
}

// Init initializes itopo with the particular validator. A topology must be
// initialized by calling SetStatic.
func Init(id string, svc proto.ServiceType, clbks Callbacks) {
	if st != nil {
		panic("Must not re-initialize itopo")
	}
	st = newState(id, svc, clbks)
}

// Get atomically gets the pointer to the current topology.
func Get() *topology.Topo {
	st.RLock()
	defer st.RUnlock()
	return st.topo.Get()
}

// SetDynamic atomically sets the dynamic topology. The returned topology is a pointer
// to the currently active topology at the end of the function call. It might differ from
// the input topology. The second return value indicates whether the in-memory
// copy of the dynamic topology has been updated.
func SetDynamic(static *topology.Topo) (*topology.Topo, bool, error) {
	return st.setDynamic(static)
}

// BeginSetDynamic checks whether setting the dynamic topology is permissible. The returned
// transaction provides a view on which topology would be active, if committed.
func BeginSetDynamic(dynamic *topology.Topo) (Transaction, error) {
	return st.beginSetDynamic(dynamic)
}

// SetStatic atomically sets the static topology. Whether semi-mutable fields are
// allowed to change can be specified using semiMutAllowed. The returned
// topology is a pointer to the currently active topology at the end of the function call.
// It might differ from the input topology (same contents as existing static,
// or dynamic set and still valid). The second return value indicates whether the in-memory
// copy of the static topology has been updated.
func SetStatic(static *topology.Topo, semiMutAllowed bool) (*topology.Topo, bool, error) {
	return st.setStatic(static, semiMutAllowed)
}

// BeginSetStatic checks whether setting the static topology is permissible. The returned
// transaction provides a view on which topology would be active, if committed.
func BeginSetStatic(static *topology.Topo, semiMutAllowed bool) (Transaction, error) {
	return st.beginSetStatic(static, semiMutAllowed)
}

// Transaction allows to get a view on which topology will be active without committing
// to the topology update yet.
type Transaction struct {
	// candidateTopo contains the view of what the static and dynamic topologies
	// will be when the transaction is successfully committed.
	candidateTopo topo
	// staticAtTxStart stores a snapshot of the currently active static
	// topology at transaction start.
	staticAtTxStart *topology.Topo
	// inputStatic stores the provided static topology.
	inputStatic *topology.Topo
	// inputDynamic stores the provided dynamic topology.
	inputDynamic *topology.Topo
}

// Commit commits the change. An error is returned, if the static topology changed in the meantime.
func (tx *Transaction) Commit() error {
	st.Lock()
	defer st.Unlock()
	if tx.staticAtTxStart != st.topo.static {
		return common.NewBasicError("Static topology changed in the meantime", nil)
	}
	if !tx.IsUpdate() {
		return nil
	}
	// Do transaction for static topology updated.
	if tx.inputStatic != nil {
		st.updateStatic(tx.inputStatic)
		return nil
	}
	// Do transaction from dynamic topology update.
	st.topo.dynamic = tx.inputDynamic
	return nil
}

// Get returns the topology that will be active if the transaction is committed.
func (tx *Transaction) Get() *topology.Topo {
	return tx.candidateTopo.Get()
}

// IsUpdate indicates whether the transaction will cause an update.
func (tx *Transaction) IsUpdate() bool {
	if tx.inputStatic != nil {
		return tx.candidateTopo.static == tx.inputStatic
	}
	return tx.candidateTopo.dynamic == tx.inputDynamic
}

// topo stores the currently active static and dynamic topologies.
type topo struct {
	static  *topology.Topo
	dynamic *topology.Topo
}

// Get returns the dynamic topology if it is set and has not expired. Otherwise,
// the static topology is returned.
func (t *topo) Get() *topology.Topo {
	if t.dynamic != nil && t.dynamic.Active(time.Now()) {
		return t.dynamic
	}
	return t.static
}

// state keeps track of the active topologies and enforces update rules.
type state struct {
	sync.RWMutex
	topo      topo
	validator validator
	clbks     Callbacks
}

func newState(id string, svc proto.ServiceType, clbks Callbacks) *state {
	s := &state{
		validator: validatorFactory(id, svc),
		clbks:     clbks,
	}
	return s
}

// setDynamic atomically sets the dynamic topology.
func (s *state) setDynamic(dynamic *topology.Topo) (*topology.Topo, bool, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.dynamicPreCheck(dynamic); err != nil {
		return nil, false, err
	}
	if err := s.validator.Validate(dynamic, s.topo.static, false); err != nil {
		return nil, false, err
	}
	if keepOld(dynamic, s.topo.dynamic) {
		return s.topo.Get(), false, nil
	}
	s.topo.dynamic = dynamic
	return s.topo.Get(), true, nil
}

func (s *state) beginSetDynamic(dynamic *topology.Topo) (Transaction, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.dynamicPreCheck(dynamic); err != nil {
		return Transaction{}, err
	}
	if err := s.validator.Validate(dynamic, s.topo.static, false); err != nil {
		return Transaction{}, err
	}
	tx := Transaction{
		candidateTopo:   s.topo,
		staticAtTxStart: s.topo.static,
		inputDynamic:    dynamic,
	}
	if !keepOld(tx.inputDynamic, tx.candidateTopo.dynamic) {
		// The dynamic topology is only updated if it differs and is valid longer.
		tx.candidateTopo.dynamic = dynamic
	}
	return tx, nil
}

func (s *state) dynamicPreCheck(dynamic *topology.Topo) error {
	if dynamic == nil {
		return common.NewBasicError("Provided topology must not be nil", nil)
	}
	if s.topo.static == nil {
		return common.NewBasicError("Static topology must be set", nil)
	}
	now := time.Now()
	if !dynamic.Active(now) {
		return common.NewBasicError("Dynamic topology must be active", nil,
			"ts", dynamic.Timestamp, "now", now, "expiry", dynamic.Expiry())
	}
	return nil
}

// setStatic atomically sets the static topology.
func (s *state) setStatic(static *topology.Topo, allowed bool) (*topology.Topo, bool, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.validator.Validate(static, s.topo.static, allowed); err != nil {
		return nil, false, err
	}
	// Only update static topology if the new one is different or valid for longer.
	if keepOld(static, s.topo.static) {
		return s.topo.Get(), false, nil
	}
	s.updateStatic(static)
	return s.topo.Get(), true, nil
}

func (s *state) beginSetStatic(static *topology.Topo, allowed bool) (Transaction, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.validator.Validate(static, s.topo.static, allowed); err != nil {
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
	// Drop dynamic from candidate topo if it will be dropped when committing the transaction.
	if s.validator.MustDropDynamic(tx.inputStatic, tx.staticAtTxStart) {
		tx.candidateTopo.dynamic = nil
	}
	tx.candidateTopo.static = static
	return tx, nil
}

// updateStatic updates the static topology, if necessary, and calls the corresponding callbacks.
func (s *state) updateStatic(static *topology.Topo) {
	// Drop dynamic topology if necessary.
	if s.validator.MustDropDynamic(static, s.topo.static) && s.topo.dynamic != nil {
		s.topo.dynamic = nil
		call(s.clbks.DropDynamic)
	}
	s.topo.static = static
	call(s.clbks.UpdateStatic)
}

func keepOld(newTopo, oldTopo *topology.Topo) bool {
	return topoEq(newTopo, oldTopo) && !expiresLater(newTopo, oldTopo)
}

func topoEq(newTopo, oldTopo *topology.Topo) bool {
	return cmp.Equal(newTopo, oldTopo, cmpopts.IgnoreFields(
		topology.Topo{}, "Timestamp", "TimestampHuman", "TTL"))
}

func expiresLater(newTopo, oldTopo *topology.Topo) bool {
	if oldTopo == nil {
		return true
	}
	newExpiry := newTopo.Expiry()
	oldExpiry := oldTopo.Expiry()
	return !oldExpiry.IsZero() && (newExpiry.IsZero() || newExpiry.After(oldExpiry))
}

func call(clbk func()) {
	if clbk != nil {
		go func() {
			defer log.LogPanicAndExit()
			clbk()
		}()
	}
}
