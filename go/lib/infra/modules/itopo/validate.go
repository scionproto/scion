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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

type dynDropper interface {
	// MustDropDynamic indicates whether the dynamic topology shall be dropped.
	MustDropDynamic(topo, oldTopo *topology.Topo) bool
}

// validator is used to validate that the topology update is permissible.
type validator interface {
	dynDropper
	// Validate checks that the topology update is valid according to the mutability rules.
	// The validation rules differ between service types. However, at the very least, it
	// is checked that topo is not nil and the immutable parts do not change.
	Validate(topo, oldTopo *topology.Topo, allowed bool) error
}

func validatorFactory(svc proto.ServiceType) validator {
	switch svc {
	case proto.ServiceType_unset:
		return &validatorWrap{&generalValidator{}}
	case proto.ServiceType_br:
		// FIXME(roosd): add validator for border router.
		return &validatorWrap{&generalValidator{}}
	default:
		// FIMXE(roosd): add validator for service.
		return &validatorWrap{&generalValidator{}}
	}
}

// validatorWrap wraps the internalValidator and implements validator.
type validatorWrap struct {
	internalValidator
}

// Validate checks that the topology update is valid.
func (v *validatorWrap) Validate(topo, oldTopo *topology.Topo, allowed bool) error {
	if err := v.General(topo); err != nil {
		return err
	}
	if err := v.Immutable(topo, oldTopo); err != nil {
		return err
	}
	if err := v.SemiMutable(topo, oldTopo, allowed); err != nil {
		return err
	}
	return nil
}

type internalValidator interface {
	dynDropper
	// General checks that the topology is generally valid. The exact check is implementation
	// specific to the validator. However, at the very least, this check ensures that the
	// provided topology is non-nil.
	General(topo *topology.Topo) error
	// Immutable checks that the immutable parts of the topology do not change.
	Immutable(topo, oldTopo *topology.Topo) error
	// SemiMutable checks that the semi-mutable parts of the topology update are valid.
	SemiMutable(topo, oldTopo *topology.Topo, allowed bool) error
}

var _ internalValidator = (*generalValidator)(nil)

// generalValidator is used to validate updates if no specific element information
// is set. It only checks that the topology is non-nil and the immutable fields are
// not modified.
type generalValidator struct{}

func (v *generalValidator) General(topo *topology.Topo) error {
	if topo == nil {
		return common.NewBasicError("Topo must not be nil", nil)
	}
	return nil
}

func (v *generalValidator) Immutable(topo, oldTopo *topology.Topo) error {
	if oldTopo == nil {
		return nil
	}
	if !topo.ISD_AS.Equal(oldTopo.ISD_AS) {
		return common.NewBasicError("IA is immutable", nil,
			"expected", oldTopo.ISD_AS, "actual", topo.ISD_AS)
	}
	if topo.Core != oldTopo.Core {
		return common.NewBasicError("Core is immutable", nil,
			"expected", oldTopo.Core, "actual", topo.Core)
	}
	if topo.Overlay != oldTopo.Overlay {
		return common.NewBasicError("Overlay is immutable", nil,
			"expected", oldTopo.Overlay, "actual", topo.Overlay)
	}
	if topo.MTU != oldTopo.MTU {
		return common.NewBasicError("MTU is immutable", nil,
			"expected", oldTopo.MTU, "actual", topo.MTU)
	}
	return nil
}
func (*generalValidator) SemiMutable(_, _ *topology.Topo, _ bool) error {
	return nil
}

func (*generalValidator) MustDropDynamic(_, _ *topology.Topo) bool {
	return false
}
