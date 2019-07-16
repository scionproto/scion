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
package trc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/scrypto"
	trc "github.com/scionproto/scion/go/lib/scrypto/trcv2"
)

func TestPrimaryASesValidateInvariant(t *testing.T) {
	tests := map[string]struct {
		Primaries trc.PrimaryASes
		Assertion assert.ErrorAssertionFunc
	}{
		"Missing online key": {
			Primaries: trc.PrimaryASes{
				a110: trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Voting},
					Keys: map[trc.KeyType]trc.KeyMeta{
						trc.OfflineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{1, 110, 1},
						},
					},
				},
			},
			Assertion: assert.Error,
		},
		"Unexpected key": {
			Primaries: trc.PrimaryASes{
				a110: trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Core},
					Keys: map[trc.KeyType]trc.KeyMeta{
						trc.OfflineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{1, 110, 1},
						},
					},
				},
			},
			Assertion: assert.Error,
		},
		"Invalid attributes": {
			Primaries: trc.PrimaryASes{
				a110: trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Authoritative},
				},
			},
			Assertion: assert.Error,
		},
		"With Valid": {
			Primaries: trc.PrimaryASes{
				a110: trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Core},
				},
			},
			Assertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Assertion(t, test.Primaries.ValidateInvariant())
		})
	}
}

func TestPrimaryASesWithAttribute(t *testing.T) {
	primaries := trc.PrimaryASes{
		a110: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Voting, trc.Core},
		},
		a120: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Issuing},
		},
		a130: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Authoritative, trc.Core},
		},
	}
	tests := map[string]struct {
		Attribute trc.Attribute
		Expected  trc.PrimaryASes
	}{
		"Authoritative": {
			Attribute: trc.Authoritative,
			Expected: trc.PrimaryASes{
				a130: primaries[a130],
			},
		},
		"Core": {
			Attribute: trc.Core,
			Expected: trc.PrimaryASes{
				a110: primaries[a110],
				a130: primaries[a130],
			},
		},
		"Issuing": {
			Attribute: trc.Issuing,
			Expected: trc.PrimaryASes{
				a120: primaries[a120],
			},
		},
		"Voting": {
			Attribute: trc.Voting,
			Expected: trc.PrimaryASes{
				a110: primaries[a110],
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.Expected, primaries.WithAttribute(test.Attribute))
		})
	}
}

func TestPrimaryASesCount(t *testing.T) {
	primaries := trc.PrimaryASes{
		a110: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Voting, trc.Core, trc.Issuing},
		},
		a120: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Authoritative, trc.Voting, trc.Core},
		},
		a130: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Authoritative, trc.Core, trc.Issuing},
		},
		a140: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Issuing},
		},
		a150: trc.PrimaryAS{
			Attributes: trc.Attributes{trc.Core},
		},
	}
	assert.Equal(t, 2, primaries.Count(trc.Authoritative))
	assert.Equal(t, 4, primaries.Count(trc.Core))
	assert.Equal(t, 3, primaries.Count(trc.Issuing))
	assert.Equal(t, 2, primaries.Count(trc.Voting))
}

func TestPrimaryASValidateInvariant(t *testing.T) {
	tests := map[string]struct {
		Primary   trc.PrimaryAS
		Assertion assert.ErrorAssertionFunc
	}{
		"Non-Core and Authoritative": {
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Authoritative},
				Keys: map[trc.KeyType]trc.KeyMeta{
					trc.OfflineKey: {},
					trc.OnlineKey:  {},
				},
			},
			Assertion: assert.Error,
		},
		"Voting AS without online key": {
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Voting},
				Keys: map[trc.KeyType]trc.KeyMeta{
					trc.OfflineKey: {},
				},
			},
			Assertion: assert.Error,
		},
		"Voting AS without offline key": {
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Voting},
				Keys: map[trc.KeyType]trc.KeyMeta{
					trc.OnlineKey: {},
				},
			},
			Assertion: assert.Error,
		},
		"Voting AS with issuing key": {
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Voting},
				Keys: map[trc.KeyType]trc.KeyMeta{
					trc.OnlineKey: {},
				},
			},
			Assertion: assert.Error,
		},
		"Issuer AS without issuing key": {
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Issuing},
				Keys:       make(map[trc.KeyType]trc.KeyMeta),
			},
			Assertion: assert.Error,
		},
		"Issuer AS with online key": {
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Issuing},
				Keys: map[trc.KeyType]trc.KeyMeta{
					trc.IssuingKey: {},
					trc.OnlineKey:  {},
				},
			},
			Assertion: assert.Error,
		},
		"Valid Core": {
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Core},
			},
			Assertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Assertion(t, test.Primary.ValidateInvariant())
		})
	}
}
