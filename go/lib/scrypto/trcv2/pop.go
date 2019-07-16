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

package trc

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	// MissingProofOfPossession indicates that the proof of possession is missing.
	MissingProofOfPossession = "missing proof of possession"
	// UnexpectedProofOfPossession indicates that the proof of possession is missing.
	UnexpectedProofOfPossession = "unexpected proof of possession"
)

type popValidator struct {
	TRC        *TRC
	KeyChanges *KeyChanges
	pops       map[addr.AS]map[KeyType]struct{}
}

func (v *popValidator) checkProofOfPossession() error {
	v.pops = make(map[addr.AS]map[KeyType]struct{}, len(v.TRC.ProofOfPossession))
	for as, types := range v.TRC.ProofOfPossession {
		m := make(map[KeyType]struct{}, len(types))
		for _, t := range types {
			m[t] = struct{}{}
		}
		v.pops[as] = m
	}
	if err := v.popForModType(v.KeyChanges.Fresh); err != nil {
		return err
	}
	if err := v.popForModType(v.KeyChanges.Modified); err != nil {
		return err
	}
	for as, types := range v.pops {
		if len(types) > 0 {
			return common.NewBasicError(UnexpectedProofOfPossession, nil,
				"AS", as, "keyTypes", types)
		}
	}
	return nil
}

// popForModType checks that all new keys have a proof of possession in the TRC.
// Additionally, it removes all visited pops from the mapping.
func (v *popValidator) popForModType(changes map[KeyType]map[addr.AS]KeyMeta) error {
	for keyType, m := range changes {
		if err := v.popForKeyType(keyType, m); err != nil {
			return err
		}
	}
	return nil
}

func (v *popValidator) popForKeyType(keyType KeyType, m map[addr.AS]KeyMeta) error {
	for as := range m {
		var pop bool
		for _, t := range v.TRC.ProofOfPossession[as] {
			pop = pop || t == keyType
		}
		if !pop {
			return common.NewBasicError(MissingProofOfPossession, nil, "AS", as, "keyType", keyType)
		}
		delete(v.pops[as], keyType)
	}
	return nil
}
