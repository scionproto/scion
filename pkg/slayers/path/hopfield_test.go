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

package path_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path"
)

func TestHopSerializeDecode(t *testing.T) {
	want := &path.HopField{
		IngressRouterAlert: true,
		EgressRouterAlert:  true,
		ExpTime:            63,
		ConsIngress:        1,
		ConsEgress:         0,
		Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	}
	b := make([]byte, path.HopLen)
	assert.NoError(t, want.SerializeTo(b))

	got := &path.HopField{}
	assert.NoError(t, got.DecodeFromBytes(b))
	assert.Equal(t, want, got)
}

func TestExpTimeFromDuration(t *testing.T) {
	tests := map[string]struct {
		d       time.Duration
		ExpTime uint8
		ErrorF  assert.ErrorAssertionFunc
	}{
		"Zero": {
			d:       0,
			ExpTime: 0,
			ErrorF:  assert.Error,
		},
		"Max": {
			d:       path.MaxTTL,
			ExpTime: 255,
			ErrorF:  assert.NoError,
		},
		"Overflow": {
			d:       (path.MaxTTL + 1),
			ExpTime: 0,
			ErrorF:  assert.Error,
		},
		"Underflow": {
			d:       -1,
			ExpTime: 0,
			ErrorF:  assert.Error,
		},
		"Max-1": {
			d:       (path.MaxTTL - 1),
			ExpTime: 254,
			ErrorF:  assert.NoError,
		},
		"Half": {
			d:       (path.MaxTTL / 2),
			ExpTime: 127,
			ErrorF:  assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			expTime, err := path.ExpTimeFromDuration(test.d)
			test.ErrorF(t, err)
			assert.Equal(t, test.ExpTime, expTime)
		})
	}
}
