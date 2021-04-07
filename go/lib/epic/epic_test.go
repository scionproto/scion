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
	"github.com/stretchr/testify/require"

	libepic "github.com/scionproto/scion/go/lib/epic"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestPrepareMacInput(t *testing.T) {
	e := createEpicPath()
	var ts uint32 = 1257894000 // = [4a f9 f0 70]

	testCases := map[string]struct {
		ScionHeader *slayers.SCION
		errorFunc   assert.ErrorAssertionFunc
		Want        []byte
	}{
		"Correct input": {
			ScionHeader: createScionCmnAddrHdr(0),
			errorFunc:   assert.NoError,
			Want: []byte(
				"\x00\x4a\xf9\xf0\x70\x00\x00\x00\x01\x02\x00\x00\x03" +
					"\x00\x02\xff\x00\x00\x00\x02\x22\x0a\x00\x00\x64\x00\x78" +
					"\x00\x00\x00\x00\x00"),
		},
		"Invalid source address length": {
			ScionHeader: createScionCmnAddrHdr(3),
			errorFunc:   assert.Error,
		},
		"SCION header nil": {
			ScionHeader: nil,
			errorFunc:   assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			got, err := libepic.PrepareMacInput(e.PktID, tc.ScionHeader, ts)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.Want, got)
		})
	}
}

func TestCreateTimestamp(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	testCases := map[string]struct {
		Timestamp time.Time
		errorFunc assert.ErrorAssertionFunc
		Expected  time.Duration
	}{
		"Timestamp way too far in the past": {
			Timestamp: time.Unix(0, 0),
			errorFunc: assert.Error,
		},
		"Timestamp one day and 64 minutes in the past": {
			Timestamp: now.Add(-createTimeHMS(24, 64, 0)),
			errorFunc: assert.Error,
		},
		"Timestamp one day and 63 minutes in the past": {
			Timestamp: now.Add(-createTimeHMS(24, 63, 0)),
			errorFunc: assert.NoError,
			Expected:  createTimeHMS(24, 63, 0)/libepic.TimestampResolution - 1,
		},
		"Timestamp one day in the past": {
			Timestamp: now.Add(-createTimeHMS(24, 0, 0)),
			errorFunc: assert.NoError,
			Expected:  createTimeHMS(24, 0, 0)/libepic.TimestampResolution - 1,
		},
		"Timestamp one minute in the past": {
			Timestamp: now.Add(-createTimeHMS(0, 1, 0)),
			errorFunc: assert.NoError,
			Expected:  createTimeHMS(0, 1, 0)/libepic.TimestampResolution - 1,
		},
		"Timestamp one second in the past": {
			Timestamp: now.Add(-createTimeHMS(0, 0, 1)),
			errorFunc: assert.NoError,
			Expected:  createTimeHMS(0, 0, 1)/libepic.TimestampResolution - 1,
		},
		"Timestamp less than 21 microseconds in the past": {
			Timestamp: now.Add(-21 * time.Microsecond),
			errorFunc: assert.NoError,
			Expected:  createTimeHMS(0, 0, 0),
		},
		"Timestamp in the future": {
			Timestamp: now.Add(1 * time.Nanosecond),
			errorFunc: assert.Error,
		},
		"Timestamp way too far in the future": {
			Timestamp: now.Add(createTimeHMS(^uint32(0), 0, 0)),
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			epicTS, err := libepic.CreateTimestamp(tc.Timestamp, now)
			tc.errorFunc(t, err)
			assert.Equal(t, uint32(tc.Expected), epicTS)
		})
	}
}

func TestVerifyTimestamp(t *testing.T) {
	// The current time
	now := time.Now().Truncate(time.Second)

	// The Info Field was timestamped 1 minute ago
	timeInfoCreation := now.Add(-time.Minute)

	// Create epicTS that represents the current time. It will be modified in the tests in order to
	// check different cases.
	epicTS, err := libepic.CreateTimestamp(timeInfoCreation, now)
	require.NoError(t, err)

	// Abbreviate max. clock skew, abbreviate sum of max. clock skew and max. packet lifetime.
	// Both are represented as the number of intervals they contain, where an interval is
	// 21 microseconds long (which corresponds to the precision of the EPIC timestamp).
	cs := uint32((libepic.MaxClockSkew / 21).Microseconds())
	csAndPl := uint32(((libepic.MaxClockSkew + libepic.MaxPacketLifetime) / 21).Microseconds())

	testCases := map[string]struct {
		EpicTS    uint32
		errorFunc assert.ErrorAssertionFunc
	}{
		"Timestamp one minute old": {
			EpicTS:    0,
			errorFunc: assert.Error,
		},
		"Timestamp older than max. clock skew plus max. packet lifetime": {
			EpicTS:    epicTS - csAndPl,
			errorFunc: assert.Error,
		},
		"Timestamp valid but in the past": {
			EpicTS:    epicTS - csAndPl + 1,
			errorFunc: assert.NoError,
		},
		"Timestamp valid": {
			EpicTS:    epicTS,
			errorFunc: assert.NoError,
		},
		"Timestamp valid but in future": {
			EpicTS:    epicTS + cs,
			errorFunc: assert.NoError,
		},
		"Timestamp newer than clock skew": {
			EpicTS:    epicTS + cs + 1,
			errorFunc: assert.Error,
		},
		"Timestamp way too far in future": {
			EpicTS:    ^uint32(0),
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			// Verify the timestamp now
			err := libepic.VerifyTimestamp(timeInfoCreation, tc.EpicTS, now)
			tc.errorFunc(t, err)
		})
	}
}

func TestVerifyHVF(t *testing.T) {
	// Create packet
	s := createScionCmnAddrHdr(0)
	now := time.Now().Truncate(time.Second)
	timestamp := uint32(now.Add(-time.Minute).Unix())
	epicTS, _ := libepic.CreateTimestamp(now.Add(-time.Minute), time.Now())
	pktID := epic.PktID{
		Timestamp: epicTS,
		Counter:   libepic.PktCounterFromCore(1, 2),
	}

	// Use random authenticators
	authPenultimate := []byte("fcdc8202502d452e")
	authLast := []byte("f5fcc4ce2250db36")

	// Generate PHVF and LHVF
	PHVF, err := libepic.CalcMac(authPenultimate, pktID, s, timestamp)
	assert.NoError(t, err)
	LHVF, err := libepic.CalcMac(authLast, pktID, s, timestamp)
	assert.NoError(t, err)

	testCases := map[string]struct {
		Authenticator []byte
		PktID         epic.PktID
		ScionHeader   *slayers.SCION
		Timestamp     uint32
		HVF           []byte
		errorFunc     assert.ErrorAssertionFunc
	}{
		"PHVF valid": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			errorFunc:     assert.NoError,
		},
		"PHVF with wrong authenticator": {
			Authenticator: []byte("074487bf22e46742"),
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			errorFunc:     assert.Error,
		},
		"PHVF with empty pktID": {
			Authenticator: authPenultimate,
			PktID:         epic.PktID{},
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			errorFunc:     assert.Error,
		},
		"PHVF with SCION header nil": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   nil,
			Timestamp:     timestamp,
			HVF:           PHVF,
			errorFunc:     assert.Error,
		},
		"PHVF with wrong timestamp": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp - 10,
			HVF:           PHVF,
			errorFunc:     assert.Error,
		},
		"PHVF is invalid": {
			Authenticator: authPenultimate,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           []byte("706c"),
			errorFunc:     assert.Error,
		},
		"LHVF valid": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           LHVF,
			errorFunc:     assert.NoError,
		},
		"LHVF with wrong authenticator": {
			Authenticator: []byte("074487bf22e46742"),
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           LHVF,
			errorFunc:     assert.Error,
		},
		"LHVF with empty pktID": {
			Authenticator: authLast,
			PktID:         epic.PktID{},
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           PHVF,
			errorFunc:     assert.Error,
		},
		"LHVF with SCION header nil": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   nil,
			Timestamp:     timestamp,
			HVF:           LHVF,
			errorFunc:     assert.Error,
		},
		"LHVF with wrong timestamp": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp - 10,
			HVF:           LHVF,
			errorFunc:     assert.Error,
		},
		"LHVF is invalid": {
			Authenticator: authLast,
			PktID:         pktID,
			ScionHeader:   s,
			Timestamp:     timestamp,
			HVF:           []byte("706c"),
			errorFunc:     assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			err = libepic.VerifyHVF(tc.Authenticator, tc.PktID,
				tc.ScionHeader, tc.Timestamp, tc.HVF)
			tc.errorFunc(t, err)
		})
	}
}

func TestPktCounterFromCore(t *testing.T) {
	testCases := map[string]struct {
		CoreID      uint8
		CoreCounter uint32
		Want        uint32
	}{
		"Basic": {
			CoreID:      0x01,
			CoreCounter: 0x1234,
			Want:        0x01001234,
		},
		"Overflow CoreCounter": {
			CoreID:      0x01,
			CoreCounter: 0xffffffff,
			Want:        0x01ffffff,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			got := libepic.PktCounterFromCore(tc.CoreID, tc.CoreCounter)
			assert.Equal(t, tc.Want, got)
		})
	}
}

func TestCoreFromPktCounter(t *testing.T) {
	testCases := map[string]struct {
		PktCounter      uint32
		WantCoreID      uint8
		WantCoreCounter uint32
	}{
		"Basic": {
			PktCounter:      0x12345678,
			WantCoreID:      0x12,
			WantCoreCounter: 0x345678,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			coreID, coreCounter := libepic.CoreFromPktCounter(tc.PktCounter)
			assert.Equal(t, tc.WantCoreID, coreID)
			assert.Equal(t, tc.WantCoreCounter, coreCounter)
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
		Timestamp: 1,
		Counter:   libepic.PktCounterFromCore(2, 3),
	}
	epicpath := &epic.Path{
		PktID: pktID,
		PHVF:  []byte{1, 2, 3, 4},
		LHVF:  []byte{5, 6, 7, 8},
	}
	return epicpath
}

func createTimeHMS(hours, minutes, seconds uint32) time.Duration {
	return (time.Duration(hours) * time.Hour) +
		(time.Duration(minutes) * time.Minute) +
		(time.Duration(seconds) * time.Second)
}
