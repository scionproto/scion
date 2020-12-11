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

package libepic_test

import (
	"math"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/libepic"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestMacInputGeneration(t *testing.T) {
	want := []byte(
		"\x00\x4a\xf9\xf0\x70\x00\x00\x00\x01\x02\x00\x00\x03" +
			"\x00\x02\xff\x00\x00\x00\x02\x22\x0a\x00\x00\x64\x00\x78" +
			"\x00\x00\x00\x00\x00")
	s := createScionCmnAddrHdr()
	e := createEpicPath()
	var ts uint32 = 1257894000 // = [4a f9 f0 70]
	got, err := libepic.PrepareMacInput(e, s, ts)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestTimestamp(t *testing.T) {
	testCases := []uint64{0, 1, math.MaxInt32}
	for i := 1; i <= 10; i++ {
		testCases = append(testCases, randUint64())
	}
	for _, want := range testCases {
		tsRel, coreID, coreCounter := libepic.ParseEpicTimestamp(want)
		got := libepic.CreateEpicTimestamp(tsRel, coreID, coreCounter)
		assert.Equal(t, want, got)
	}
}

func TestTsRel(t *testing.T) {
	now := uint32(time.Now().Unix())
	testCases := map[uint32]bool{
		0:                    false,
		now - (30 * 60 * 60): false,
		now - (24 * 60 * 60): true,
		now - 60:             true,
		now - 1:              true,
		now + 5:              false,
	}
	for timestamp, want := range testCases {
		_, err := libepic.CreateTsRel(timestamp)
		if want == true {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}

func TestTimestampVerification(t *testing.T) {
	now := uint32(time.Now().Unix())
	timestamp := now - 60
	tsRel, err := libepic.CreateTsRel(timestamp)
	assert.NoError(t, err)

	cs := uint32(libepic.ClockSkewMs)
	csAndPl := uint32(libepic.ClockSkewMs + libepic.PacketLifetimeMs)

	testCases := map[uint32]bool{
		0:                           false,
		tsRel - 2*(csAndPl*1000/21): false,
		tsRel - (csAndPl*1000/21)/2: true,
		tsRel:                       true,
		tsRel + (cs*1000/21)/2:      true,
		tsRel + 2*(cs*1000/21):      false,
		math.MaxInt32:               false,
	}

	for tsRel, want := range testCases {
		packetTimestamp := libepic.CreateEpicTimestamp(tsRel, 1, 2)
		got := libepic.VerifyTimestamp(timestamp, packetTimestamp)
		assert.Equal(t, want, got)
	}
}

func TestHVFVerification(t *testing.T) {
	// Create packet
	s := createScionCmnAddrHdr()
	timestamp := uint32(time.Now().Unix()) - 60
	tsRel, _ := libepic.CreateTsRel(timestamp)
	packetTimestamp := libepic.CreateEpicTimestamp(tsRel, 1, 2)
	epicpath := &epic.EpicPath{
		ScionRaw:        createScionPath(2, 4),
		PacketTimestamp: packetTimestamp,
	}

	// Generate random authenticators
	authPenultimate := randBytes(16)
	authLast := randBytes(16)

	// Penultimate hop verification
	macPenultimate, err := libepic.CalculateEpicMac(authPenultimate, epicpath, s, timestamp)
	assert.NoError(t, err)
	epicpath.PHVF = macPenultimate
	got, err := libepic.VerifyHVF(authPenultimate, epicpath, s, timestamp, false)
	assert.NoError(t, err)
	assert.True(t, got)
	got, err = libepic.VerifyHVF(randBytes(16), epicpath, s, timestamp, false)
	assert.NoError(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authPenultimate, nil, s, timestamp, false)
	assert.Error(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authPenultimate, epicpath, nil, timestamp, false)
	assert.Error(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authPenultimate, epicpath, s, timestamp-10, false)
	assert.NoError(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authPenultimate, epicpath, s, timestamp, true)
	assert.NoError(t, err)
	assert.False(t, got)

	// Increase current hop
	epicpath.ScionRaw = createScionPath(3, 4)

	// Last hop verification
	macLast, err := libepic.CalculateEpicMac(authLast, epicpath, s, timestamp)
	assert.NoError(t, err)
	epicpath.LHVF = macLast
	got, err = libepic.VerifyHVF(authLast, epicpath, s, timestamp, true)
	assert.NoError(t, err)
	assert.True(t, got)
	got, err = libepic.VerifyHVF(randBytes(16), epicpath, s, timestamp, true)
	assert.NoError(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authLast, nil, s, timestamp, true)
	assert.Error(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authLast, epicpath, nil, timestamp, true)
	assert.Error(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authLast, epicpath, s, timestamp+10, true)
	assert.NoError(t, err)
	assert.False(t, got)
	got, err = libepic.VerifyHVF(authLast, epicpath, s, timestamp, false)
	assert.NoError(t, err)
	assert.False(t, got)
}

func TestPenultimateHop(t *testing.T) {
	testCases := map[*scion.Raw]bool{
		createScionPath(0, 2):  true,
		createScionPath(1, 2):  false,
		createScionPath(2, 2):  false,
		createScionPath(0, -1): false,
		createScionPath(5, 7):  true,
		createScionPath(6, 7):  false,
		createScionPath(7, 7):  false,
	}
	for scionRaw, want := range testCases {
		got, _ := libepic.IsPenultimateHop(scionRaw)
		assert.Equal(t, want, got)
	}
}

func TestLastHop(t *testing.T) {
	testCases := map[*scion.Raw]bool{
		createScionPath(0, 2):  false,
		createScionPath(1, 2):  true,
		createScionPath(2, 2):  false,
		createScionPath(0, -1): false,
		createScionPath(5, 7):  false,
		createScionPath(6, 7):  true,
		createScionPath(7, 7):  false,
	}
	for scionRaw, want := range testCases {
		got, _ := libepic.IsLastHop(scionRaw)
		assert.Equal(t, want, got)
	}
}

func createScionCmnAddrHdr() *slayers.SCION {
	spkt := &slayers.SCION{
		SrcAddrLen: 0,
		SrcIA:      xtest.MustParseIA("2-ff00:0:222"),
		PayloadLen: 120,
	}
	ip4Addr := &net.IPAddr{IP: net.ParseIP("10.0.0.100")}
	spkt.SetSrcAddr(ip4Addr)
	return spkt
}

func createEpicPath() *epic.EpicPath {
	ts := libepic.CreateEpicTimestamp(1, 2, 3)
	epicpath := &epic.EpicPath{
		PacketTimestamp: ts,
		PHVF:            []byte{1, 2, 3, 4},
		LHVF:            []byte{5, 6, 7, 8},
	}
	return epicpath
}

func createScionPath(currHF uint8, numHops int) *scion.Raw {
	scionRaw := &scion.Raw{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: currHF,
			},
			NumHops: numHops,
		},
	}
	return scionRaw
}

func randUint64() uint64 {
	return uint64(rand.Uint32())<<32 + uint64(rand.Uint32())
}

func randBytes(l uint16) []byte {
	r := make([]byte, l)
	rand.Read(r)
	return r
}
