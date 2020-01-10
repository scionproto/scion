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
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

type genTRC struct {
	ISD               *addr.ISD                  `json:"isd,omitempty"`
	Version           *scrypto.Version           `json:"trc_version,omitempty"`
	BaseVersion       *scrypto.Version           `json:"base_version,omitempty"`
	Description       *string                    `json:"description,omitempty"`
	VotingQuorum      *uint8                     `json:"voting_quorum,omitempty"`
	FormatVersion     *trc.FormatVersion         `json:"format_version,omitempty"`
	GracePeriod       *trc.Period                `json:"grace_period,omitempty"`
	TrustResetAllowed *bool                      `json:"trust_reset_allowed,omitempty"`
	Validity          *scrypto.Validity          `json:"validity,omitempty"`
	PrimaryASes       *trc.PrimaryASes           `json:"primary_ases,omitempty"`
	Votes             *map[addr.AS]trc.KeyType   `json:"votes,omitempty"`
	ProofOfPossession *map[addr.AS][]trc.KeyType `json:"proof_of_possession,omitempty"`
	UnknownField      string                     `json:"unknown_field,omitempty"`
}

func TestTRCUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Modify         func(*genTRC)
		ExpectedErrMsg string
	}{
		"valid": {
			Modify: func(*genTRC) {},
		},
		"ISD not set": {
			Modify: func(g *genTRC) {
				g.ISD = nil
			},
			ExpectedErrMsg: trc.ErrISDNotSet.Error(),
		},
		"Version not set": {
			Modify: func(g *genTRC) {
				g.Version = nil
			},
			ExpectedErrMsg: trc.ErrVersionNotSet.Error(),
		},
		"BaseVersion not set": {
			Modify: func(g *genTRC) {
				g.BaseVersion = nil
			},
			ExpectedErrMsg: trc.ErrBaseVersionNotSet.Error(),
		},
		"Description not set": {
			Modify: func(g *genTRC) {
				g.Description = nil
			},
			ExpectedErrMsg: trc.ErrDescriptionNotSet.Error(),
		},
		"VotingQuorum not set": {
			Modify: func(g *genTRC) {
				g.VotingQuorum = nil
			},
			ExpectedErrMsg: trc.ErrVotingQuorumNotSet.Error(),
		},
		"FormatVersion not set": {
			Modify: func(g *genTRC) {
				g.FormatVersion = nil
			},
			ExpectedErrMsg: trc.ErrFormatVersionNotSet.Error(),
		},
		"GracePeriod not set": {
			Modify: func(g *genTRC) {
				g.GracePeriod = nil
			},
			ExpectedErrMsg: trc.ErrGracePeriodNotSet.Error(),
		},
		"TrustResetAllowed not set": {
			Modify: func(g *genTRC) {
				g.TrustResetAllowed = nil
			},
			ExpectedErrMsg: trc.ErrTrustResetAllowedNotSet.Error(),
		},
		"Validity not set": {
			Modify: func(g *genTRC) {
				g.Validity = nil
			},
			ExpectedErrMsg: trc.ErrValidityNotSet.Error(),
		},
		"PrimaryASes not set": {
			Modify: func(g *genTRC) {
				g.PrimaryASes = nil
			},
			ExpectedErrMsg: trc.ErrPrimaryASesNotSet.Error(),
		},
		"Votes not set": {
			Modify: func(g *genTRC) {
				g.Votes = nil
			},
			ExpectedErrMsg: trc.ErrVotesNotSet.Error(),
		},
		"ProofOfPossession not set": {
			Modify: func(g *genTRC) {
				g.ProofOfPossession = nil
			},
			ExpectedErrMsg: trc.ErrProofOfPossessionNotSet.Error(),
		},
		"Unknown field": {
			Modify: func(g *genTRC) {
				g.UnknownField = "And if you don't know, now you know!"
			},
			ExpectedErrMsg: `json: unknown field "unknown_field"`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			trcObj, g := newGenTRC(time.Now())
			test.Modify(g)
			b, err := json.Marshal(g)
			require.NoError(t, err)
			var parsed trc.TRC
			err = json.Unmarshal(b, &parsed)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, trcObj, &parsed)
			} else {
				require.Error(t, err)
				assert.Equal(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestFormatVersionUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  trc.FormatVersion
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte("1"),
			Expected:  1,
			Assertion: assert.NoError,
		},
		"Unsupported": {
			Input:     []byte("0"),
			Assertion: assert.Error,
		},
		"String": {
			Input:     []byte(`"0"`),
			Assertion: assert.Error,
		},
		"Garbage": {
			Input:     []byte(`"Garbage"`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var v trc.FormatVersion
			test.Assertion(t, json.Unmarshal(test.Input, &v))
			assert.Equal(t, test.Expected, v)
		})
	}
}

func TestPeriodUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid 0": {
			Input:     []byte("0"),
			Assertion: assert.NoError,
		},
		"Valid hour": {
			Input:     []byte(strconv.Itoa(int(time.Hour / time.Second))),
			Expected:  time.Hour,
			Assertion: assert.NoError,
		},
		"String": {
			Input:     []byte(`"1"`),
			Assertion: assert.Error,
		},
		"Garbage": {
			Input:     []byte(`"Garbage"`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var p trc.Period
			test.Assertion(t, json.Unmarshal(test.Input, &p))
			assert.Equal(t, test.Expected, p.Duration)
		})
	}
}

func TestPeriodMarshalJSON(t *testing.T) {
	type mockTRC struct {
		Period trc.Period `json:"period"`
	}
	tests := map[string]struct {
		// Use a struct to simulate TRC marshaling. Pointer vs value receiver.
		Input     mockTRC
		Expected  []byte
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid 0": {
			Input:     mockTRC{},
			Expected:  []byte(`{"period":0}`),
			Assertion: assert.NoError,
		},
		"Valid hour": {
			Input:     mockTRC{Period: trc.Period{Duration: time.Hour}},
			Expected:  []byte(`{"period":3600}`),
			Assertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(test.Input)
			test.Assertion(t, err)
			assert.Equal(t, test.Expected, b)
		})
	}
}

func newGenTRC(now time.Time) (*trc.TRC, *genTRC) {
	b := newBaseTRC(now)
	t := &genTRC{
		ISD:               &b.ISD,
		Version:           &b.Version,
		BaseVersion:       &b.BaseVersion,
		Description:       &b.Description,
		VotingQuorum:      b.VotingQuorumPtr,
		FormatVersion:     &b.FormatVersion,
		GracePeriod:       b.GracePeriod,
		TrustResetAllowed: b.TrustResetAllowedPtr,
		Validity:          b.Validity,
		PrimaryASes:       &b.PrimaryASes,
		Votes:             &b.Votes,
		ProofOfPossession: &b.ProofOfPossession,
	}
	return b, t
}
