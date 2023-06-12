// Copyright 2023 ETH Zurich
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

package drkey

import (
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/spao"
)

type FakeProvider struct {
	KeyDuration      time.Duration
	AcceptanceWindow time.Duration
}

func (p *FakeProvider) GetASHostKey(
	validTime time.Time,
	_ addr.IA,
	_ addr.Host,
) (drkey.ASHostKey, error) {

	duration := int64(p.KeyDuration / time.Second)
	idxCurrent := validTime.Unix() / duration
	epochCurrent := newEpoch(idxCurrent, duration)
	return drkey.ASHostKey{
		Key:   drkey.Key{},
		Epoch: epochCurrent,
	}, nil
}

func (p *FakeProvider) GetKeyWithinAcceptanceWindow(
	t time.Time,
	timestamp uint64,
	dstIA addr.IA,
	dstAddr addr.Host,
) (drkey.ASHostKey, error) {

	keys, err := p.getASHostTreble(t, dstIA, dstAddr)
	if err != nil {
		return drkey.ASHostKey{}, err
	}

	awBegin := t.Add(-(p.AcceptanceWindow + time.Nanosecond))
	awEnd := t.Add(p.AcceptanceWindow)

	absTimePrevious := spao.AbsoluteTimestamp(keys[0], timestamp)
	absTimeCurrent := spao.AbsoluteTimestamp(keys[1], timestamp)
	absTimeNext := spao.AbsoluteTimestamp(keys[2], timestamp)
	switch {
	case absTimeCurrent.After(awBegin) && absTimeCurrent.Before(awEnd):
		return keys[1], nil
	case absTimePrevious.After(awBegin) && absTimePrevious.Before(awEnd):
		return keys[0], nil
	case absTimeNext.After(awBegin) && absTimeNext.Before(awEnd):
		return keys[2], nil
	default:
		return drkey.ASHostKey{}, serrors.New("no absTime falls into the acceptance window",
			"awBegin", awBegin, "awEnd", awEnd, "absTimePrevious", absTimePrevious,
			"absTimeCurrent", absTimeCurrent, "absTimeNext", absTimeNext)
	}
}

func (p *FakeProvider) getASHostTreble(
	validTime time.Time,
	_ addr.IA,
	_ addr.Host,
) ([]drkey.ASHostKey, error) {

	duration := int64(p.KeyDuration / time.Second)
	idxCurrent := validTime.Unix() / duration
	idxPrevious, idxNext := idxCurrent-1, idxCurrent+1
	epochPrevious := newEpoch(idxPrevious, duration)
	epochCurrent := newEpoch(idxCurrent, duration)
	epochNext := newEpoch(idxNext, duration)
	return []drkey.ASHostKey{
		{
			Epoch: epochPrevious,
			Key:   drkey.Key{},
		},
		{
			Epoch: epochCurrent,
			Key:   drkey.Key{},
		},
		{
			Epoch: epochNext,
			Key:   drkey.Key{},
		},
	}, nil
}

func newEpoch(idx int64, duration int64) drkey.Epoch {
	begin := uint32(idx * duration)
	end := begin + uint32(duration)
	return drkey.NewEpoch(begin, end)
}
