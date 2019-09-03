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

package pathpol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyJsonConversion(t *testing.T) {
	policy := &ExtPolicy{
		ACL:      &ACL{Entries: []*ACLEntry{allowEntry}},
		Sequence: newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
		Options: []ExtOption{
			{
				Policy: &ExtPolicy{
					Extends: []string{"foo"},
					ACL: &ACL{
						Entries: []*ACLEntry{
							{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
							denyEntry,
						},
					},
				},
				Weight: 0,
			},
		},
	}
	jsonPol, err := json.Marshal(policy)
	require.NoError(t, err)
	var pol ExtPolicy
	err = json.Unmarshal(jsonPol, &pol)
	assert.NoError(t, err)
	assert.Equal(t, policy, &pol)
}
