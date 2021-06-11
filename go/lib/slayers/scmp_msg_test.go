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

func TestSCMPExternalInterfaceDownDecodeFromBytes(t *testing.T) {
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

func TestSCMPExternalInterfaceDownSerializeTo(t *testing.T) {
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
			t.Parallel()
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:16]
			tc.decoded.Payload = tc.raw[16:]
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

func TestSCMPInternalConnectivityDownDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPInternalConnectivityDown
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x0, 0x1, 0xff, 0x0,
				0x0, 0x0, 0x1, 0x11,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x5,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0xf,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPInternalConnectivityDown{
				IA:      xtest.MustParseIA("1-ff00:0:111"),
				Ingress: 5,
				Egress:  15,
			},
			assertFunc: assert.NoError,
		},
		"invalid": {
			raw:        bytes.Repeat([]byte{0x0}, 15),
			decoded:    &slayers.SCMPInternalConnectivityDown{},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMPInternalConnectivityDown{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:24]
			tc.decoded.Payload = tc.raw[24:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPInternalConnectivityDownSerializeTo(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPInternalConnectivityDown
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x0, 0x1, 0xff, 0x0,
				0x0, 0x0, 0x1, 0x11,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x5,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0xf,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPInternalConnectivityDown{
				IA:      xtest.MustParseIA("1-ff00:0:111"),
				Ingress: 5,
				Egress:  15,
			},
			assertFunc: assert.NoError,
		},
		//"invalid": { }, // not possible

	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:24]
			tc.decoded.Payload = tc.raw[24:]
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

func TestSCMPEchoDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPEcho
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x2a, 0x05, 0x39,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPEcho{
				Identifier: 42,
				SeqNumber:  1337,
			},
			assertFunc: assert.NoError,
		},
		"invalid": {
			raw:        []byte{0x00, 0x00, 0x00},
			decoded:    &slayers.SCMPEcho{},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMPEcho{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPEchoSerializeTo(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPEcho
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x2a, 0x05, 0x39,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPEcho{
				Identifier: 42,
				SeqNumber:  1337,
			},
			assertFunc: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
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

func TestSCMPParameterProblemDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPParameterProblem
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x00, 0x00, 0x42,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPParameterProblem{
				Pointer: 66,
			},
			assertFunc: assert.NoError,
		},
		"invalid": {
			raw:        bytes.Repeat([]byte{0x0}, 1),
			decoded:    &slayers.SCMPParameterProblem{},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMPParameterProblem{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPParameterProblemSerializeTo(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPParameterProblem
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x00, 0x00, 0x42,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPParameterProblem{
				Pointer: 66,
			},
			assertFunc: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
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

func TestSCMPTracerouteDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPTraceroute
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x2a, 0x00, 0x09,
				0x00, 0x01, 0xff, 0x00,
				0x00, 0x00, 0x01, 0x11,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x05,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPTraceroute{
				Identifier: 42,
				Sequence:   9,
				IA:         xtest.MustParseIA("1-ff00:0:111"),
				Interface:  5,
			},
			assertFunc: assert.NoError,
		},
		"invalid": {
			raw:        bytes.Repeat([]byte{0x0}, 19),
			decoded:    &slayers.SCMPTraceroute{},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMPTraceroute{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:20]
			tc.decoded.Payload = tc.raw[20:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPTracerouteSerializeTo(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPTraceroute
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x2a, 0x00, 0x09,
				0x00, 0x01, 0xff, 0x00,
				0x00, 0x00, 0x01, 0x11,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x05,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPTraceroute{
				Identifier: 42,
				Sequence:   9,
				IA:         xtest.MustParseIA("1-ff00:0:111"),
				Interface:  5,
			},
			assertFunc: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:20]
			tc.decoded.Payload = tc.raw[20:]
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

func TestSCMPDestinationUnreachableDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPDestinationUnreachable
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x00, 0x00, 0x00,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded:    &slayers.SCMPDestinationUnreachable{},
			assertFunc: assert.NoError,
		},
		"valid non-zero ignored": {
			raw: append([]byte{
				0xff, 0xff, 0xff, 0xff,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded:    &slayers.SCMPDestinationUnreachable{},
			assertFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMPDestinationUnreachable{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPDestinationUnreachableSerializeTo(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPDestinationUnreachable
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x00, 0x00, 0x00,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded:    &slayers.SCMPDestinationUnreachable{},
			assertFunc: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
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

func TestSCMPPacketTooBigDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPPacketTooBig
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x00, 0x05, 0x7c,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPPacketTooBig{
				MTU: 1404,
			},
			assertFunc: assert.NoError,
		},
		"invalid": {
			raw:        bytes.Repeat([]byte{0x0}, 1),
			decoded:    &slayers.SCMPPacketTooBig{},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMPPacketTooBig{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPPacketTooBigSerializeTo(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMPPacketTooBig
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x00, 0x00, 0x05, 0x7c,
			}, bytes.Repeat([]byte{0xff}, 10)...),
			decoded: &slayers.SCMPPacketTooBig{
				MTU: 1404,
			},
			assertFunc: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := gopacket.SerializeOptions{}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
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
