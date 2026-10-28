// Copyright 2026 SCION Association
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

package segverifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/segment/segverifier"
	"github.com/scionproto/scion/private/segment/verifier"
)

func TestVerifyTimestamp(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	lifetime := path.ExpTimeToDuration(63)

	// Timestamps have a granularity of one second,
	// so 337s and 338s are the closest offsets to the allowance of 337.5s.
	testCases := map[string]struct {
		timestamp time.Time
		expTimes  []uint8
		wantErr   error
	}{
		"current": {
			timestamp: now,
			expTimes:  []uint8{63, 63},
		},
		"future within allowance": {
			timestamp: now.Add(337 * time.Second),
			expTimes:  []uint8{63, 63},
		},
		"future beyond allowance": {
			timestamp: now.Add(338 * time.Second),
			expTimes:  []uint8{63, 63},
			wantErr:   segverifier.ErrFutureTimestamp,
		},
		"expired within allowance": {
			timestamp: now.Add(-lifetime - 337*time.Second),
			expTimes:  []uint8{63, 63},
		},
		"expired beyond allowance": {
			timestamp: now.Add(-lifetime - 338*time.Second),
			expTimes:  []uint8{63, 63},
			wantErr:   segverifier.ErrExpiredHop,
		},
		"one hop field expired": {
			timestamp: now.Add(-time.Hour),
			expTimes:  []uint8{63, 0},
			wantErr:   segverifier.ErrExpiredHop,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := segverifier.VerifyTimestamp(testSegment(t, tc.timestamp, tc.expTimes...), now)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, segverifier.ErrSegment)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestStartVerificationChecksTimestamp(t *testing.T) {
	now := time.Now()
	current := &seg.Meta{
		Type:    seg.TypeDown,
		Segment: testSegment(t, now, 63),
	}
	future := &seg.Meta{
		Type:    seg.TypeDown,
		Segment: testSegment(t, now.Add(time.Hour), 63),
	}
	expired := &seg.Meta{
		Type:    seg.TypeDown,
		Segment: testSegment(t, now.Add(-7*time.Hour), 63),
	}

	results, n := segverifier.StartVerification(context.Background(),
		verifier.AcceptAllVerifier{}, nil, []*seg.Meta{current, future, expired})
	errs := make(map[*seg.Meta]error, n)
	for range n {
		r := <-results
		errs[r.Unit.SegMeta] = r.SegError()
	}
	assert.NoError(t, errs[current])
	assert.ErrorIs(t, errs[future], segverifier.ErrSegment)
	assert.ErrorIs(t, errs[future], segverifier.ErrFutureTimestamp)
	assert.ErrorIs(t, errs[expired], segverifier.ErrSegment)
	assert.ErrorIs(t, errs[expired], segverifier.ErrExpiredHop)
}

func testSegment(t *testing.T, timestamp time.Time, expTimes ...uint8) *seg.PathSegment {
	info, err := seg.NewInfo(timestamp, 1)
	require.NoError(t, err)
	pseg := &seg.PathSegment{Info: info}
	for _, expTime := range expTimes {
		pseg.ASEntries = append(pseg.ASEntries, seg.ASEntry{
			HopEntry: seg.HopEntry{HopField: seg.HopField{ExpTime: expTime}},
		})
	}
	return pseg
}
