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

package slayers_test

import (
	"bytes"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSCMPMsgExternalInterfaceDownDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPExternalInterfaceDown
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x0, 0x1, 0xff, 0x0,
				0x0, 0x0, 0x1, 0x11,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x5,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPExternalInterfaceDown{
				IA:   xtest.MustParseIA("1-ff00:0:111"),
				IfID: uint64(5),
			},
			assertFunc: assert.NoError,
		},
		"invalid": {
			raw:        bytes.Repeat([]byte{0x0}, 15),
			decoded:    &slayers.SCMPExternalInterfaceDown{},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMPExternalInterfaceDown{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:16]
			tc.decoded.Payload = tc.raw[16:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPMsgExternalInterfaceDownSerializeTo(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPExternalInterfaceDown
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x0, 0x1, 0xff, 0x0,
				0x0, 0x0, 0x1, 0x11,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x5,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPExternalInterfaceDown{
				IA:   xtest.MustParseIA("1-ff00:0:111"),
				IfID: uint64(5),
			},
			assertFunc: assert.NoError,
		},
		//"invalid": { }, // not possible

	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:16]
			tc.decoded.Payload = tc.raw[16:]
			t.Parallel()
			buffer := gopacket.NewSerializeBuffer()
			err := tc.decoded.SerializeTo(buffer, opts)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.raw[:len(tc.decoded.Contents)], buffer.Bytes())
		})
	}
}
