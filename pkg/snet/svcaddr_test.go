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

package snet_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/snet"
)

func TestSVCAddrInterface(t *testing.T) {
	var x any = &snet.SVCAddr{}
	_, ok := x.(net.Addr)
	assert.True(t, ok, "should implement net interface")
}

func TestSVCAddrString(t *testing.T) {
	tests := map[string]struct {
		input *snet.SVCAddr
		want  string
	}{
		"nil": {
			input: &snet.SVCAddr{},
			want:  "0-0,<SVC:0x0000>",
		},
	}
	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			a := tc.input.String()
			assert.Equal(t, a, tc.want)
		})
	}
}
