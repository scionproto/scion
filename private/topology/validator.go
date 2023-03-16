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
	"reflect"
	"sync"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// DefaultValidator is the default topology update validator.
type DefaultValidator struct {
	v        *validatorWrap
	initOnce sync.Once
}

func (v *DefaultValidator) Validate(new, old *RWTopology) error {
	v.init()
	return v.v.Validate(new, old)
}

func (v *DefaultValidator) init() {
	v.initOnce.Do(func() {
		v.v = &validatorWrap{&generalValidator{}}
	})
}

// ControlValidator is the validator that should be used for control services.

type ControlValidator struct {
	ID       string
	v        *validatorWrap
	initOnce sync.Once
}

func (v *ControlValidator) Validate(new, old *RWTopology) error {
	v.init()
	return v.v.Validate(new, old)
}

func (v *ControlValidator) init() {
	v.initOnce.Do(func() {
		v.v = &validatorWrap{&svcValidator{id: v.ID, svc: Control}}
	})
}

// RouterValidator is the validator that should be used for routers.

type RouterValidator struct {
	ID       string
	v        *validatorWrap
	initOnce sync.Once
}

func (v *RouterValidator) Validate(new, old *RWTopology) error {
	v.init()
	return v.v.Validate(new, old)
}

func (v *RouterValidator) init() {
	v.initOnce.Do(func() {
		v.v = &validatorWrap{&routerValidator{id: v.ID}}
	})
}

type internalValidator interface {
	// General checks that the topology is generally valid. The exact check is implementation
	// specific to the validator. However, at the very least, this check ensures that the
	// provided topology is non-nil.
	General(topo *RWTopology) error
	// Immutable checks that the immutable parts of the topology do not change.
	Immutable(topo, oldTopo *RWTopology) error
}

// validatorWrap wraps the internalValidator and implements validator.
type validatorWrap struct {
	internalValidator
}

// Validate checks that the topology update is valid.
func (v *validatorWrap) Validate(new, old *RWTopology) error {
	if err := v.General(new); err != nil {
		return err
	}
	if err := v.Immutable(new, old); err != nil {
		return err
	}
	return nil
}

// generalValidator is used to validate updates if no specific element information
// is set. It only checks that the topology is non-nil and the immutable fields are
// not modified.
type generalValidator struct{}

func (v *generalValidator) General(topo *RWTopology) error {
	if topo == nil {
		return serrors.New("Topo must not be nil")
	}
	return nil
}

func (v *generalValidator) Immutable(new, old *RWTopology) error {
	if old == nil {
		return nil
	}
	if !new.IA.Equal(old.IA) {
		return serrors.New("IA is immutable",
			"expected", old.IA, "actual", new.IA)
	}
	if new.IsCore != old.IsCore {
		return serrors.New("IsCore is immutable",
			"expected", old.IsCore, "actual", new.IsCore)
	}
	if new.MTU != old.MTU {
		return serrors.New("MTU is immutable",
			"expected", old.MTU, "actual", new.MTU)
	}
	return nil
}

// svcValidator is used to validate updates if the element is a infra service.
// It checks that the service is present, and only permissible updates are done.
type svcValidator struct {
	generalValidator
	id  string
	svc ServiceType
}

func (v *svcValidator) General(topo *RWTopology) error {
	if err := v.generalValidator.General(topo); err != nil {
		return err
	}
	if _, err := topo.GetTopoAddr(v.id, v.svc); err != nil {
		return serrors.New("Topo must contain service", "id", v.id, "svc", v.svc)
	}
	return nil
}

func (v *svcValidator) Immutable(new, old *RWTopology) error {
	if old == nil {
		return nil
	}
	if err := v.generalValidator.Immutable(new, old); err != nil {
		return err
	}
	// We already checked that the service is in the map.
	nAddr, _ := new.GetTopoAddr(v.id, v.svc)
	oAddr, _ := old.GetTopoAddr(v.id, v.svc)
	// FIXME(scrye): The equality check below is protocol specific. Use reflect.DeepEqual for now,
	// but it's better to define what "entry must not change" actually means w.r.t. all possible
	// internal addresses.
	if !reflect.DeepEqual(nAddr, oAddr) {
		return serrors.New("Local service entry must not change",
			"id", v.id, "svc", v.svc, "expected", oAddr, "actual", nAddr)
	}
	return nil
}

// routerValidator is used to validate updates if the element is a router. It
// checks that the router is present, and only permissible updates are done.
type routerValidator struct {
	generalValidator
	id string
}

func (v *routerValidator) General(topo *RWTopology) error {
	if err := v.generalValidator.General(topo); err != nil {
		return err
	}
	if _, ok := topo.BR[v.id]; !ok {
		return serrors.New("Topo must contain border router", "id", v.id)
	}
	return nil
}

func (v *routerValidator) Immutable(new, old *RWTopology) error {
	if old == nil {
		return nil
	}
	if err := v.generalValidator.Immutable(new, old); err != nil {
		return err
	}
	if new.BR[v.id].InternalAddr.String() != old.BR[v.id].InternalAddr.String() {
		return serrors.New("InternalAddrs is immutable", "expected",
			old.BR[v.id].InternalAddr, "actual", new.BR[v.id].InternalAddr)
	}
	return nil
}
