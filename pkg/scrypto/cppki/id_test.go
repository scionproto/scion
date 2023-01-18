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

package cppki_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestTRCIDValidate(t *testing.T) {
	testCases := map[string]struct {
		ID  cppki.TRCID
		Err error
	}{
		"valid": {
			ID: cppki.TRCID{
				ISD:    12,
				Base:   1,
				Serial: 2,
			},
		},
		"serial < base": {
			ID: cppki.TRCID{
				ISD:    12,
				Base:   3,
				Serial: 2,
			},
			Err: cppki.ErrSerialBeforeBase,
		},
		"wildcard ISD": {
			ID: cppki.TRCID{
				ISD:    0,
				Base:   1,
				Serial: 1,
			},
			Err: cppki.ErrWildcardISD,
		},
		"base == 0": {
			ID: cppki.TRCID{
				ISD:    12,
				Base:   0,
				Serial: 2,
			},
			Err: cppki.ErrReservedNumber,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.ID.Validate()
			assert.ErrorIs(t, err, tc.Err)

		})
	}
}

func TestNewTRCID(t *testing.T) {
	testCases := map[string]struct {
		trcStr string
		trcID  cppki.TRCID
		err    error
	}{
		"valid TRC ID string": {
			trcStr: "ISD1-B1-S1",
			trcID: cppki.TRCID{
				ISD:    addr.ISD(1),
				Base:   scrypto.Version(1),
				Serial: scrypto.Version(1),
			},
		},
		"valid TRC ID string with bigger versions": {
			trcStr: "ISD12-B21-S112",
			trcID: cppki.TRCID{
				ISD:    addr.ISD(12),
				Base:   scrypto.Version(21),
				Serial: scrypto.Version(112),
			},
		},
		"invalid TRC ID string": {
			trcStr: "ISD1-B1-S",
			trcID:  cppki.TRCID{},
			err:    cppki.ErrInvalidTRCIDString,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			trcID, err := cppki.TRCIDFromString(tc.trcStr)
			assert.Equal(t, trcID, tc.trcID)
			assert.ErrorIs(t, err, tc.err)
		})
	}
}
