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

package cppki

import (
	"crypto/x509/pkix"
	"reflect"
	"slices"
)

func equalName(name, other pkix.Name) bool {
	rdn1, rdn2 := name.ToRDNSequence(), other.ToRDNSequence()
	// quick check: if the strings don't match, they can't be equal.
	if rdn1.String() != rdn2.String() {
		return false
	}
	return equalRDNSequence(rdn1, rdn2)
}

func equalRDNSequence(rdn1, rdn2 pkix.RDNSequence) bool {
	return slices.EqualFunc(rdn1, rdn2, func(a, b pkix.RelativeDistinguishedNameSET) bool {
		return len(a) == len(b) && equalRDNSET(a, b)
	})
}

func equalRDNSET(rdns1, rdns2 pkix.RelativeDistinguishedNameSET) bool {
	return rdnSETSubset(rdns1, rdns2) && rdnSETSubset(rdns2, rdns1)
}

// rdnSETSubset checks that rdns1 is a subset of rdns2.
func rdnSETSubset(rdns1, rdns2 pkix.RelativeDistinguishedNameSET) bool {
	for _, av1 := range rdns1 {
		found := slices.ContainsFunc(rdns2, func(av2 pkix.AttributeTypeAndValue) bool {
			return av1.Type.Equal(av2.Type) && reflect.DeepEqual(av1.Value, av2.Value)
		})
		if !found {
			return false
		}
	}
	return true
}
