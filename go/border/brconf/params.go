// Copyright 2018 Anapaya Systems
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

package brconf

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
)

type BR struct {
	// Profile enables cpu and memory profiling.
	Profile bool
	// RollbackFailAction indicates the action that should be taken
	// if the rollback fails.
	RollbackFailAction FailAction
}

func (b *BR) InitDefaults() {
	if b.RollbackFailAction != FailActionContinue {
		b.RollbackFailAction = FailActionFatal
	}
}

type Discovery struct {
	idiscovery.Config
	// AllowSemiMutable indicates whether changes to the semi-mutable
	// section in the static topology are allowed.
	AllowSemiMutable bool
}

type FailAction string

const (
	// FailActionFatal indicates that the process exits on error.
	FailActionFatal FailAction = "Fatal"
	// FailActionContinue indicates that the process continues on error.
	FailActionContinue FailAction = "Continue"
)

func (f *FailAction) UnmarshalText(text []byte) error {
	switch FailAction(text) {
	case FailActionFatal:
		*f = FailActionFatal
	case FailActionContinue:
		*f = FailActionContinue
	default:
		return common.NewBasicError("Unknown FailAction", nil, "input", string(text))
	}
	return nil
}
