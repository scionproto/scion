// Copyright 2026 ETH Zurich
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

package drkeyutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/spao"
)

func TestGetKeyWithinAcceptanceWindow(t *testing.T) {
	epochDuration := 24 * time.Hour
	acceptanceWindow := 1 * time.Minute
	provider := &FakeProvider{
		EpochDuration:    epochDuration,
		AcceptanceWindow: acceptanceWindow,
	}

	epochStart := time.Unix(0, 0).Add(epochDuration)

	t.Run("valid: packet sent and received within same epoch", func(t *testing.T) {
		now := epochStart.Add(30 * time.Second)
		sendTime := now.Add(-1 * time.Second)
		currentEpoch := drkey.NewEpoch(
			uint32(epochStart.Unix()),
			uint32(epochStart.Add(epochDuration).Unix()),
		)
		relTime, err := spao.RelativeTimestamp(currentEpoch, sendTime)
		require.NoError(t, err)

		key, err := provider.GetKeyWithinAcceptanceWindow(
			now, relTime, 0, addr.Host{},
		)
		require.NoError(t, err)
		assert.Equal(t, currentEpoch, key.Epoch)
	})

	t.Run("valid: packet sent in previous epoch within grace period", func(t *testing.T) {
		// Current time is 2s into the new epoch (within grace period of 5s)
		now := epochStart.Add(2 * time.Second)
		// Sender sent 1s ago, which is 1s into the new epoch
		// But using the previous epoch's key, the send time should be
		// within grace period
		prevEpochStart := epochStart.Add(-epochDuration)
		prevEpoch := drkey.NewEpoch(
			uint32(prevEpochStart.Unix()),
			uint32(epochStart.Unix()),
		)
		sendTime := epochStart.Add(-1 * time.Second)
		relTime, err := spao.RelativeTimestamp(prevEpoch, sendTime)
		require.NoError(t, err)

		key, err := provider.GetKeyWithinAcceptanceWindow(
			now, relTime, 0, addr.Host{},
		)
		require.NoError(t, err)
		assert.Equal(t, prevEpoch, key.Epoch)
	})

	t.Run("invalid: timestamp outside epoch + grace period", func(t *testing.T) {
		// EpochDuration = 1 day, AcceptanceWindow = 1 minute
		// Current time t = E_i + 1 minute
		// Timestamp encodes "1 day and 30 seconds" relative to E_{i-1}
		// But K_{i-1} is not valid at E_{i} + 30 seconds (past grace period)
		now := epochStart.Add(1 * time.Minute)
		prevEpochStart := epochStart.Add(-epochDuration)
		prevEpoch := drkey.NewEpoch(
			uint32(prevEpochStart.Unix()),
			uint32(epochStart.Unix()),
		)
		sendTime := prevEpochStart.Add(epochDuration + 30*time.Second)
		relTime, err := spao.RelativeTimestamp(prevEpoch, sendTime)
		require.NoError(t, err)

		_, err = provider.GetKeyWithinAcceptanceWindow(
			now, relTime, 0, addr.Host{},
		)
		assert.Error(t, err)
	})

	t.Run("valid: timestamp at epoch boundary within grace period", func(t *testing.T) {
		// Send time is exactly at epoch end + 3s (within 5s grace period)
		now := epochStart.Add(4 * time.Second)
		prevEpochStart := epochStart.Add(-epochDuration)
		prevEpoch := drkey.NewEpoch(
			uint32(prevEpochStart.Unix()),
			uint32(epochStart.Unix()),
		)
		sendTime := epochStart.Add(3 * time.Second)
		relTime, err := spao.RelativeTimestamp(prevEpoch, sendTime)
		require.NoError(t, err)

		key, err := provider.GetKeyWithinAcceptanceWindow(
			now, relTime, 0, addr.Host{},
		)
		require.NoError(t, err)
		assert.Equal(t, prevEpoch, key.Epoch)
	})

	t.Run("invalid: absTime before acceptance window", func(t *testing.T) {
		// Current time is 1 min into the epoch. Sender supposedly sent
		// 40s ago, which is outside the acceptance window of [-30s, +30s].
		now := epochStart.Add(1 * time.Minute)
		currentEpoch := drkey.NewEpoch(
			uint32(epochStart.Unix()),
			uint32(epochStart.Add(epochDuration).Unix()),
		)
		sendTime := now.Add(-40 * time.Second)
		relTime, err := spao.RelativeTimestamp(currentEpoch, sendTime)
		require.NoError(t, err)

		_, err = provider.GetKeyWithinAcceptanceWindow(
			now, relTime, 0, addr.Host{},
		)
		assert.Error(t, err)
	})

	t.Run("invalid: absTime after acceptance window", func(t *testing.T) {
		// Current time is 5 min into the epoch. Sender supposedly sent
		// 40s in the future, which is outside the acceptance window.
		now := epochStart.Add(5 * time.Minute)
		currentEpoch := drkey.NewEpoch(
			uint32(epochStart.Unix()),
			uint32(epochStart.Add(epochDuration).Unix()),
		)
		sendTime := now.Add(40 * time.Second)
		relTime, err := spao.RelativeTimestamp(currentEpoch, sendTime)
		require.NoError(t, err)

		_, err = provider.GetKeyWithinAcceptanceWindow(
			now, relTime, 0, addr.Host{},
		)
		assert.Error(t, err)
	})

	t.Run("valid: absTime at edge of acceptance window", func(t *testing.T) {
		// Current time is 5 min into the epoch. Sender sent 29s ago,
		// just within the acceptance window of [-30s, +30s].
		now := epochStart.Add(5 * time.Minute)
		currentEpoch := drkey.NewEpoch(
			uint32(epochStart.Unix()),
			uint32(epochStart.Add(epochDuration).Unix()),
		)
		sendTime := now.Add(-29 * time.Second)
		relTime, err := spao.RelativeTimestamp(currentEpoch, sendTime)
		require.NoError(t, err)

		key, err := provider.GetKeyWithinAcceptanceWindow(
			now, relTime, 0, addr.Host{},
		)
		require.NoError(t, err)
		assert.Equal(t, currentEpoch, key.Epoch)
	})
}
