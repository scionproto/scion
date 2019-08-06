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

package conf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatingAsConf(t *testing.T) {
	tests := map[string]struct {
		as  *As
		err string
	}{
		"With empty AS": {
			as:  &As{},
			err: ErrAsCertMissing,
		},
		"With empty Issuer inside AS Cert": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "",
					BaseCert: &BaseCert{
						TRCVersion:  1,
						Version:     1,
						RawValidity: "180s",
					},
				},
			},
			err: ErrIssuerMissing,
		},
		"With empty Issuer in different format inside AS Cert": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "0-0",
					BaseCert: &BaseCert{
						TRCVersion:  1,
						Version:     1,
						RawValidity: "180s",
					},
				},
			},
			err: ErrIssuerMissing,
		},
		"With invalid TRCVersion inside BaseCert": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						Version:     1,
						RawValidity: "180s",
					},
				},
			},
			err: ErrTRCVersionNotSet,
		},
		"With invalid Version for BaseCert": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						TRCVersion:  1,
						RawValidity: "180s",
					},
				},
			},
			err: ErrVersionNotSet,
		},
		"With invalid RawValidity for BaseCert": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						TRCVersion:  1,
						Version:     1,
						RawValidity: "180",
					},
				},
			},
			err: ErrInvalidValidityDuration,
		},
		"With validity set to 0 for BaseCert": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						TRCVersion: 1,
						Version:    1,
					},
				},
			},
			err: ErrValidityDurationNotSet,
		},
		"With valid AS Cert": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						TRCVersion:  1,
						Version:     1,
						RawValidity: "180s",
					},
				},
			},
			err: "",
		},
		"With invalid sign algorithm": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						SignAlgorithm: "curve25519xsalsa20poly1305",
						TRCVersion:    1,
						Version:       1,
						RawValidity:   "180s",
					},
				},
			},
			err: ErrInvalidSignAlgorithm,
		},
		"With invalid enc algorithm": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						EncAlgorithm: "ed25519",
						TRCVersion:   1,
						Version:      1,
						RawValidity:  "180s",
					},
				},
			},
			err: ErrInvalidEncAlgorithm,
		},
		"With invalid online key": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						TRCVersion:  1,
						Version:     1,
						RawValidity: "180s",
					},
				},
				KeyAlgorithms: &KeyAlgorithms{
					Online: "foo",
				},
			},
			err: ErrInvalidSignAlgorithm,
		},
		"With invalid offline key": {
			as: &As{
				AsCert: &AsCert{
					Issuer: "1-ff00:0:10",
					BaseCert: &BaseCert{
						TRCVersion:  1,
						Version:     1,
						RawValidity: "180s",
					},
				},
				KeyAlgorithms: &KeyAlgorithms{
					Offline: "foo",
				},
			},
			err: ErrInvalidSignAlgorithm,
		},
	}
	for scenario, test := range tests {
		t.Run(scenario, func(t *testing.T) {
			err := test.as.validate()
			if test.err != "" {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), test.err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
