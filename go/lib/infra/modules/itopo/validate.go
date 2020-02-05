// Copyright 2019 Anapaya Systems
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
	"reflect"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// validator is used to validate that the topology update is permissible.
type validator interface {
	// Validate checks that the topology update is valid.
	Validate(topo, oldTopo *topology.RWTopology) error
}

func validatorFactory(id string, svc proto.ServiceType) validator {
	switch svc {
	case proto.ServiceType_unset:
		return &validatorWrap{&generalValidator{}}
	case proto.ServiceType_br:
		// FIXME(roosd): add validator for border router.
		return &validatorWrap{&brValidator{id: id}}
	default:
		// FIMXE(roosd): add validator for service.
		return &validatorWrap{&svcValidator{id: id, svc: svc}}
	}
}

// validatorWrap wraps the internalValidator and implements validator.
type validatorWrap struct {
	internalValidator
}

// Validate checks that the topology update is valid.
func (v *validatorWrap) Validate(topo, oldTopo *topology.RWTopology) error {
	if err := v.General(topo); err != nil {
		return err
	}
	if err := v.Immutable(topo, oldTopo); err != nil {
		return err
	}
	return nil
}

type internalValidator interface {
	// General checks that the topology is generally valid. The exact check is implementation
	// specific to the validator. However, at the very least, this check ensures that the
	// provided topology is non-nil.
	General(topo *topology.RWTopology) error
	// Immutable checks that the immutable parts of the topology do not change.
	Immutable(topo, oldTopo *topology.RWTopology) error
}

var _ internalValidator = (*generalValidator)(nil)

// generalValidator is used to validate updates if no specific element information
// is set. It only checks that the topology is non-nil and the immutable fields are
// not modified.
type generalValidator struct{}

func (v *generalValidator) General(topo *topology.RWTopology) error {
	if topo == nil {
		return serrors.New("Topo must not be nil")
	}
	return nil
}

func (v *generalValidator) Immutable(topo, oldTopo *topology.RWTopology) error {
	if oldTopo == nil {
		return nil
	}
	if !topo.IA.Equal(oldTopo.IA) {
		return common.NewBasicError("IA is immutable", nil,
			"expected", oldTopo.IA, "actual", topo.IA)
	}
	if !topo.Attributes.Equal(oldTopo.Attributes) {
		return common.NewBasicError("Attributes are immutable", nil,
			"expected", oldTopo.Attributes, "actual", topo.Attributes)
	}
	if topo.MTU != oldTopo.MTU {
		return common.NewBasicError("MTU is immutable", nil,
			"expected", oldTopo.MTU, "actual", topo.MTU)
	}
	return nil
}

var _ internalValidator = (*svcValidator)(nil)

// svcValidator is used to validate updates if the element is a infra service.
// It checks that the service is present, and only permissible updates are done.
type svcValidator struct {
	generalValidator
	id  string
	svc proto.ServiceType
}

func (v *svcValidator) General(topo *topology.RWTopology) error {
	if err := v.generalValidator.General(topo); err != nil {
		return err
	}
	if _, err := topo.GetTopoAddr(v.id, v.svc); err != nil {
		return common.NewBasicError("Topo must contain service", nil, "id", v.id, "svc", v.svc)
	}
	return nil
}

func (v *svcValidator) Immutable(topo, oldTopo *topology.RWTopology) error {
	if oldTopo == nil {
		return nil
	}
	if err := v.generalValidator.Immutable(topo, oldTopo); err != nil {
		return err
	}
	// We already checked that the service is in the map.
	nAddr, _ := topo.GetTopoAddr(v.id, v.svc)
	oAddr, _ := oldTopo.GetTopoAddr(v.id, v.svc)
	// FIXME(scrye): The equality check below is protocol specific. Use reflect.DeepEqual for now,
	// but it's better to define what "entry must not change" actually means w.r.t. all possible
	// internal addresses.
	if !reflect.DeepEqual(nAddr, oAddr) {
		return common.NewBasicError("Local service entry must not change", nil,
			"id", v.id, "svc", v.svc, "expected", oAddr, "actual", nAddr)
	}
	return nil
}

var _ internalValidator = (*brValidator)(nil)

// brValidator is used to validate updates if the element is a border router.
// It checks that the border router is present, and only permissible updates
// are done.
type brValidator struct {
	generalValidator
	id string
}

func (v *brValidator) General(topo *topology.RWTopology) error {
	if err := v.generalValidator.General(topo); err != nil {
		return err
	}
	if _, ok := topo.BR[v.id]; !ok {
		return common.NewBasicError("Topo must contain border router", nil, "id", v.id)
	}
	return nil
}

func (v *brValidator) Immutable(topo, oldTopo *topology.RWTopology) error {
	if oldTopo == nil {
		return nil
	}
	if err := v.generalValidator.Immutable(topo, oldTopo); err != nil {
		return err
	}
	if topo.BR[v.id].InternalAddr.String() != oldTopo.BR[v.id].InternalAddr.String() {
		return common.NewBasicError("InternalAddrs is immutable", nil, "expected",
			oldTopo.BR[v.id].InternalAddr, "actual", topo.BR[v.id].InternalAddr)
	}
	if !reflect.DeepEqual(topo.BR[v.id].CtrlAddrs, oldTopo.BR[v.id].CtrlAddrs) {
		return common.NewBasicError("CtrlAddrs is immutable", nil, "expected",
			oldTopo.BR[v.id].CtrlAddrs, "actual", topo.BR[v.id].CtrlAddrs)
	}
	return nil
}
