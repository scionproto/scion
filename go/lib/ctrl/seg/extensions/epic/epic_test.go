// Copyright 2020 ETH Zurich
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

package epic_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/epic"
	"github.com/scionproto/scion/go/pkg/proto/control_plane/experimental"
)

func TestDetachedFromPB(t *testing.T) {
	tests := map[string]struct {
		Input    *experimental.EPICDetachedExtension
		Expected *epic.Detached
	}{
		"nil": {},
		"hop only": {
			Input: &experimental.EPICDetachedExtension{
				AuthHopEntry: []byte("0123456789"),
			},
			Expected: &epic.Detached{
				AuthHopEntry:    []byte("0123456789"),
				AuthPeerEntries: [][]byte{},
			},
		},
		"hop and peers": {
			Input: &experimental.EPICDetachedExtension{
				AuthHopEntry: []byte("0123456789"),
				AuthPeerEntries: [][]byte{
					[]byte("0123456789"),
					[]byte("0123456789"),
					[]byte("0123456789"),
				},
			},
			Expected: &epic.Detached{
				AuthHopEntry: []byte("0123456789"),
				AuthPeerEntries: [][]byte{
					[]byte("0123456789"),
					[]byte("0123456789"),
					[]byte("0123456789"),
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out := epic.DetachedFromPB(tc.Input)
			assert.Equal(t, tc.Expected, out)
		})
	}
}

func TestDetachedToPB(t *testing.T) {
	tests := map[string]struct {
		Input    *epic.Detached
		Expected *experimental.EPICDetachedExtension
	}{
		"nil": {},
		"hop only": {
			Input: &epic.Detached{
				AuthHopEntry: []byte("0123456789"),
			},
			Expected: &experimental.EPICDetachedExtension{
				AuthHopEntry:    []byte("0123456789"),
				AuthPeerEntries: [][]byte{},
			},
		},
		"hop and peers": {
			Input: &epic.Detached{
				AuthHopEntry: []byte("0123456789"),
				AuthPeerEntries: [][]byte{
					[]byte("0123456789"),
					[]byte("0123456789"),
					[]byte("0123456789"),
				},
			},
			Expected: &experimental.EPICDetachedExtension{
				AuthHopEntry: []byte("0123456789"),
				AuthPeerEntries: [][]byte{
					[]byte("0123456789"),
					[]byte("0123456789"),
					[]byte("0123456789"),
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out := epic.DetachedToPB(tc.Input)
			assert.Equal(t, tc.Expected, out)
		})
	}
}
