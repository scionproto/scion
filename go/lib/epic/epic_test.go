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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	libepic "github.com/scionproto/scion/go/lib/epic"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestMacInputGeneration(t *testing.T) {
	e := createEpicPath()
	var ts uint32 = 1257894000 // = [4a f9 f0 70]

	testCases := map[string]struct {
		ScionHeader *slayers.SCION
		Valid       bool
		Want        []byte
	}{
		"Correct input": {
			ScionHeader: createScionCmnAddrHdr(0),
			Valid:       true,
			Want: []byte(
				"\x00\x4a\xf9\xf0\x70\x00\x00\x00\x01\x02\x00\x00\x03" +
					"\x00\x02\xff\x00\x00\x00\x02\x22\x0a\x00\x00\x64\x00\x78" +
					"\x00\x00\x00\x00\x00"),
		},
		"Invalid source address length": {
			ScionHeader: createScionCmnAddrHdr(3),
			Valid:       false,
		},
		"SCION header nil": {
			ScionHeader: nil,
			Valid:       false,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			got, err := libepic.PrepareMacInput(&e.PktID, tc.ScionHeader, ts)

			if tc.Valid {
				assert.NoError(t, err)
				assert.Equal(t, tc.Want, got)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestTsRel(t *testing.T) {
	now := uint32(time.Now().Unix())
	nowNanoseconds := int64(int64(now) * 1000000000)

	testCases := map[string]struct {
		Timestamp uint32
		Valid     bool
		Expected  uint32
	}{
		"Timestamp way too far in the past": {
			Timestamp: 0,
			Valid:     false,
		},
		"Timestamp more than one day in the past": {
			Timestamp: now - (30 * 60 * 60),
			Valid:     false,
		},
		"Timestamp one day in the past": {
			Timestamp: now - (24 * 60 * 60),
			Valid:     true,
			Expected:  4114285713,
		},
		"Timestamp one minute in the past": {
			Timestamp: now - 60,
			Valid:     true,
			Expected:  2857141,
		},
		"Timestamp one second in the past": {
			Timestamp: now - 1,
			Valid:     true,
			Expected:  47618,
		},
		"Timestamp is in the future": {
			Timestamp: now + 5,
			Valid:     false,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			tsRel, err := libepic.CreateTimestamp(tc.Timestamp, nowNanoseconds)
			if tc.Valid {
				assert.NoError(t, err)
				assert.Equal(t, tc.Expected, tsRel)

			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestTimestampVerification(t *testing.T) {
	// The current time
	now := uint32(time.Now().Unix())
	nowNanoseconds := int64(now) * 1000000000

	// The Info Field was timestamped 1 minute ago
	timeInfoCreation := now - 60

	// Create tsRel that represents the current time. It will be modified in the tests in order to
	// check different cases.
	tsRel, err := libepic.CreateTimestamp(timeInfoCreation, nowNanoseconds)
	assert.NoError(t, err)

	// Abbreviate max. clock skew, abbreviate sum of max. clock skew and max. packet lifetime.
	// Both are represented as the number of intervals they contain, where an interval is
	// 21 microseconds long (which corresponds to the precision of the EPIC timestamp).
	cs := libepic.MaxClockSkew / 21
	csAndPl := (libepic.MaxClockSkew + libepic.MaxPacketLifetime) / 21

	testCases := map[string]struct {
		TsRel uint32
		Valid bool
	}{
		"Timestamp one minute old": {
			TsRel: 0,
			Valid: false,
		},
		"Timestamp older than max. clock skew plus max. packet lifetime": {
			TsRel: tsRel - csAndPl,
			Valid: false,
		},
		"Timestamp valid but in the past": {
			TsRel: tsRel - csAndPl + 1,
			Valid: true,
		},
		"Timestamp valid": {
			TsRel: tsRel,
			Valid: true,
		},
		"Timestamp valid but in future": {
			TsRel: tsRel + cs,
			Valid: true,
		},
		"Timestamp newer than clock skew": {
			TsRel: tsRel + cs + 1,
			Valid: false,
		},
		"Timestamp way too far in future": {
			TsRel: ^uint32(0),
			Valid: false,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			// Verify the timestamp now
			err := libepic.VerifyTimestamp(timeInfoCreation, tc.TsRel, nowNanoseconds)
			if tc.Valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestHVFVerification(t *testing.T) {
	// Create packet
	s := createScionCmnAddrHdr(0)
	timestamp := uint32(time.Now().Unix()) - 60
	tsRel, _ := libepic.CreateTimestamp(timestamp, time.Now().UnixNano())
	pktID := epic.PktID{
		Timestamp:   tsRel,
		CoreID:      1,
		CoreCounter: 2,
	}

	// Use random authenticators
	authPenultimate := []byte("fcdc8202502d452e")
	authLast := []byte("f5fcc4ce2250db36")

	// Generate PHVF and LHVF
	PHVF, err := libepic.CalcMac(authPenultimate, &pktID, s, timestamp)
	assert.NoError(t, err)
	LHVF, err := libepic.CalcMac(authLast, &pktID, s, timestamp)
	assert.NoError(t, err)

	testCases := map[string]struct {
		Authenticator []byte
		PktID         epic.PktID
		ScionHeader   *slayers.SCION
		Timestamp     uint32
		HVF           []byte
		Valid         bool
	}{
		"PHVF valid": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			Valid:         true,
		},
		"PHVF with wrong authenticator": {
			Authenticator: []byte("074487bf22e46742"),
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			Valid:         false,
		},
		"PHVF with empty pktID": {
			Authenticator: authPenultimate,
			PktID:         epic.PktID{},
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			Valid:         false,
		},
		"PHVF with SCION header nil": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   nil,
			Timestamp:     timestamp,
			HVF:           PHVF,
			Valid:         false,
		},
		"PHVF with wrong timestamp": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp - 10,
			HVF:           PHVF,
			Valid:         false,
		},
		"PHVF is invalid": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           []byte("706c"),
			Valid:         false,
		},
		"LHVF valid": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           LHVF,
			Valid:         true,
		},
		"LHVF with wrong authenticator": {
			Authenticator: []byte("074487bf22e46742"),
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           LHVF,
			Valid:         false,
		},
		"LHVF with empty pktID": {
			Authenticator: authLast,
			PktID:         epic.PktID{},
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			Valid:         false,
		},
		"LHVF with SCION header nil": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   nil,
			Timestamp:     timestamp,
			HVF:           LHVF,
			Valid:         false,
		},
		"LHVF with wrong timestamp": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp - 10,
			HVF:           LHVF,
			Valid:         false,
		},
		"LHVF is invalid": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           []byte("706c"),
			Valid:         false,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			err = libepic.VerifyHVF(tc.Authenticator, &tc.PktID,
				tc.ScionHeader, tc.Timestamp, tc.HVF)

			if tc.Valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func createScionCmnAddrHdr(srcAddrLen slayers.AddrLen) *slayers.SCION {
	spkt := &slayers.SCION{
		SrcIA:      xtest.MustParseIA("2-ff00:0:222"),
		PayloadLen: 120,
	}
	ip4Addr := &net.IPAddr{IP: net.ParseIP("10.0.0.100")}
	spkt.SetSrcAddr(ip4Addr)
	spkt.SrcAddrLen = srcAddrLen
	return spkt
}

func createEpicPath() *epic.Path {
	pktID := epic.PktID{
		Timestamp:   1,
		CoreID:      2,
		CoreCounter: 3,
	}
	epicpath := &epic.Path{
		PktID: pktID,
		PHVF:  []byte{1, 2, 3, 4},
		LHVF:  []byte{5, 6, 7, 8},
	}
	return epicpath
}
