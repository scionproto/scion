// Copyright 2026 Anapaya Systems
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

package topo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
)

func TestEndpointParse(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		raw     string
		want    Endpoint
		wantErr bool
	}{
		"plain": {
			raw:  "1-ff00:0:110#2",
			want: Endpoint{IA: addr.MustParseIA("1-ff00:0:110"), IfID: 2},
		},
		"with BR tag": {
			raw:  "1-ff00:0:120-A#6",
			want: Endpoint{IA: addr.MustParseIA("1-ff00:0:120"), BR: "A", IfID: 6},
		},
		"with address": {
			raw: "1-ff00:0:110#1,127.0.0.1:50000",
			want: Endpoint{
				IA: addr.MustParseIA("1-ff00:0:110"), IfID: 1, Addr: "127.0.0.1:50000",
			},
		},
		"tag and address": {
			raw: "1-ff00:0:120-B#3,10.0.0.1:50000",
			want: Endpoint{
				IA: addr.MustParseIA("1-ff00:0:120"), BR: "B", IfID: 3, Addr: "10.0.0.1:50000",
			},
		},
		"missing ifid": {raw: "1-ff00:0:110", wantErr: true},
		"bad ifid":     {raw: "1-ff00:0:110#x", wantErr: true},
		"bad ia":       {raw: "not-an-ia#1", wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var e Endpoint
			err := e.parse(tc.raw)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, e)
			// Round-trip back to the compact notation.
			var e2 Endpoint
			require.NoError(t, e2.parse(e.String()))
			assert.Equal(t, e, e2)
		})
	}
}

func TestParseAndValidateReal(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"testdata/tiny.topo", "testdata/default.topo"} {
		t.Run(f, func(t *testing.T) {
			t.Parallel()
			top, err := ParseFile(f)
			require.NoError(t, err)
			require.NoError(t, top.Validate())
			assert.NotEmpty(t, top.ASes)
			assert.NotEmpty(t, top.Links)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	base := `
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#1", linkAtoB: CHILD}
`
	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		top, err := Parse([]byte(base))
		require.NoError(t, err)
		require.NoError(t, top.Validate())
	})
	t.Run("unknown link AS", func(t *testing.T) {
		t.Parallel()
		top, err := Parse([]byte(`
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:199#1", linkAtoB: CHILD}
`))
		require.NoError(t, err)
		assert.Error(t, top.Validate())
	})
	t.Run("cert_issuer not issuing", func(t *testing.T) {
		t.Parallel()
		top, err := Parse([]byte(`
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {}
  "1-ff00:0:112": {cert_issuer: 1-ff00:0:111}
`))
		require.NoError(t, err)
		assert.Error(t, top.Validate())
	})
	t.Run("duplicate ifid", func(t *testing.T) {
		t.Parallel()
		top, err := Parse([]byte(`
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
  "1-ff00:0:112": {cert_issuer: 1-ff00:0:110}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#1", linkAtoB: CHILD}
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:112#1", linkAtoB: CHILD}
`))
		require.NoError(t, err)
		assert.Error(t, top.Validate())
	})
	t.Run("ISD missing core", func(t *testing.T) {
		t.Parallel()
		top, err := Parse([]byte(`
ASes:
  "1-ff00:0:110": {voting: true, authoritative: true, issuing: true}
`))
		require.NoError(t, err)
		assert.Error(t, top.Validate())
	})
}
