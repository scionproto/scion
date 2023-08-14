package spao_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/spao"
	"github.com/scionproto/scion/private/drkey/drkeyutil"
	"github.com/stretchr/testify/assert"
)

func TestTimestamp(t *testing.T) {
	testCases := map[string]struct {
		currentTime time.Time
		epoch       drkey.Epoch
		assertErr   assert.ErrorAssertionFunc
	}{
		"valid": {
			currentTime: time.Now().UTC(),
			epoch:       getEpoch(time.Now()),
			assertErr:   assert.NoError,
		},
		"invalid": {
			currentTime: time.Now().UTC(),
			epoch:       getEpoch(time.Now().UTC().Add(-4 * 24 * time.Hour)),
			assertErr:   assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			rt, err := spao.RelativeTimestamp(tc.epoch, tc.currentTime)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			recoveredTime := spao.AbsoluteTimestamp(tc.epoch, rt)
			assert.EqualValues(t, tc.currentTime, recoveredTime)
		})
	}
}

func getEpoch(t time.Time) drkey.Epoch {
	epochDuration := drkeyutil.LoadEpochDuration()
	duration := int64(epochDuration / time.Second)
	idx := t.Unix() / duration
	begin := uint32(idx * duration)
	end := begin + uint32(duration)
	return drkey.NewEpoch(begin, end)
}
