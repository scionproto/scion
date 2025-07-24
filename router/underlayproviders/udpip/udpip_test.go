// Copyright 2023 ETH Zurich
// Copyright 2025 SCION Association
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

package udpip

import (
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/router"
)

var (
	testKey = []byte("testkey_xxxxxxxx")
)

func computeMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf, nil)
}

// Prepares a message that is arriving at its last hop, incoming through interface 1.
func prepBaseMsg(t *testing.T, flowId uint32) *slayers.SCION {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       flowId,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        addr.MustParseIA("1-ff00:0:110"),
		SrcIA:        addr.MustParseIA("1-ff00:0:111"),
		Path:         &scion.Raw{},
		PayloadLen:   18,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 2,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(time.Now())},
		},

		HopFields: []path.HopField{
			{ConsIngress: 41, ConsEgress: 40},
			{ConsIngress: 31, ConsEgress: 30},
			{ConsIngress: 1, ConsEgress: 0},
		},
	}
	dpath.HopFields[2].Mac = computeMAC(t, testKey, dpath.InfoFields[0], dpath.HopFields[2])
	spkt.Path = dpath
	return spkt
}

func TestComputeProcId(t *testing.T) {
	randomValueBytes := []byte{1, 2, 3, 4}
	numProcs := 10000

	// ComputeProcID expects the per-receiver random number to be pre-hashed into the seed that we
	// pass.
	hashSeed := router.Fnv1aOffset32
	for _, c := range randomValueBytes {
		hashSeed = router.HashFNV1a(hashSeed, c)
	}

	// this function returns the procID as we expect it by using the  slayers.SCION serialization
	// implementation.
	referenceHash := func(s *slayers.SCION) uint32 {
		flowBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(flowBuf, s.FlowID)
		flowBuf[0] &= 0xF
		tmpBuffer := make([]byte, 100)
		hasher := fnv.New32a()
		hasher.Write(randomValueBytes)
		hasher.Write(flowBuf[1:4])
		if err := s.SerializeAddrHdr(tmpBuffer); err != nil {
			panic(err)
		}
		hasher.Write(tmpBuffer[:s.AddrHdrLen()])
		return hasher.Sum32() % uint32(numProcs)
	}

	// this helper returns the procID as the router actually makes it by using the extraction
	// from dataplane.computeProcID() along with hashFNV1a() for the seed.
	computeProcIDHelper := func(payload []byte, s *slayers.SCION) (uint32, error) {
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{FixLengths: true},
			s, gopacket.Payload(payload))
		require.NoError(t, err)
		raw := buffer.Bytes()

		return computeProcID(raw, numProcs, hashSeed)
	}
	type ret struct {
		payload []byte
		s       *slayers.SCION
	}
	// Each testcase has a function that returns a set of ret structs where
	// all rets of that set are expected to return the same hash value
	testCases := map[string]func(t *testing.T) []ret{
		"basic": func(t *testing.T) []ret {
			payload := []byte("x")
			return []ret{
				{
					payload: payload,
					s:       prepBaseMsg(t, (1<<20)-1),
				},
			}
		},
		"different payload does not affect hashing": func(t *testing.T) []ret {
			rets := make([]ret, 10)
			for i := 0; i < 10; i++ {
				rets[i].payload = make([]byte, 100)
				_, err := rand.Read(rets[i].payload)
				spkt := prepBaseMsg(t, 1)
				assert.NoError(t, err)
				rets[i].s = spkt
			}
			return rets
		},
		"flowID is extracted correctly independing of trafficId": func(t *testing.T) []ret {
			rets := make([]ret, 16)
			payload := make([]byte, 100)
			for i := 0; i < 16; i++ {
				rets[i].payload = payload
				spkt := prepBaseMsg(t, 1)
				spkt.TrafficClass = uint8(i)
				rets[i].s = spkt
			}
			return rets
		},
		"ipv4 to ipv4": func(t *testing.T) []ret {
			payload := make([]byte, 100)
			spkt := prepBaseMsg(t, 1)
			assert.NoError(t,
				spkt.SetDstAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200}))))
			assert.NoError(t,
				spkt.SetSrcAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200}))))
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, slayers.T4Ip, spkt.SrcAddrType)
			return []ret{
				{
					payload: payload,
					s:       spkt,
				},
			}
		},
		"ipv6 to ipv4": func(t *testing.T) []ret {
			payload := make([]byte, 100)
			spkt := prepBaseMsg(t, 1)
			assert.NoError(t,
				spkt.SetDstAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200}))))
			assert.NoError(t, spkt.SetSrcAddr(addr.HostIP(netip.MustParseAddr("2001:db8::68"))))
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, slayers.T16Ip, spkt.SrcAddrType)
			return []ret{
				{
					payload: payload,
					s:       spkt,
				},
			}
		},
		"svc to ipv4": func(t *testing.T) []ret {
			payload := make([]byte, 100)
			spkt := prepBaseMsg(t, 1)
			spkt.DstAddrType = slayers.T4Ip
			assert.NoError(t,
				spkt.SetDstAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200}))))
			assert.NoError(t, spkt.SetSrcAddr(addr.HostSVC(addr.SvcWildcard)))
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, slayers.T4Svc, spkt.SrcAddrType)
			return []ret{
				{
					payload: payload,
					s:       spkt,
				},
			}
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			rets := tc(t)
			if len(rets) == 0 {
				return
			}
			expected := referenceHash(rets[0].s)
			for _, r := range rets {
				actual, err := computeProcIDHelper(r.payload, r.s)
				// this tests do not test errors, hence no errors should occur
				assert.NoError(t, err)
				assert.Equal(t, expected, actual)
			}
		})
	}
}

func TestComputeProcIdErrorCases(t *testing.T) {
	type test struct {
		data          []byte
		expectedError error
	}
	testCases := map[string]test{
		"packet shorter than common header len": {
			data:          make([]byte, 10),
			expectedError: serrors.New("packet is too short"),
		},
		"packet len = CmnHdrLen + addrHdrLen": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0,
			},
			expectedError: nil,
		},
		"packet len < CmnHdrLen + addrHdrLen": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0,
			},
			expectedError: serrors.New("packet is too short"),
		},
		"packet len = CmnHdrLen + addrHdrLen (16IP)": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0x33, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0,
			},
			expectedError: nil,
		},
		"packet len < CmnHdrLen + addrHdrLen (16IP)": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0x33, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0,
			},
			expectedError: serrors.New("packet is too short"),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			randomValue := uint32(1234) // not a proper hash seed, but hash result is irrelevant.
			_, actualErr := computeProcID(tc.data, 10000, randomValue)
			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError.Error(), actualErr.Error())
			} else {
				assert.NoError(t, actualErr)
			}
		})
	}
}
