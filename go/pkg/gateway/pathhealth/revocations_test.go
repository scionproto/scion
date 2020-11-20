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

package pathhealth_test

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth"
)

var (
	testIA addr.IA = addr.IA{I: 3, A: 4}
)

func TestEmptyStore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := pathhealth.MemoryRevocationStore{}
	res := s.IsRevoked(createMockPath(ctrl, testIA, 1))
	assert.False(t, res)
	s.Cleanup()
}

func TestRevocation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := pathhealth.MemoryRevocationStore{}
	s.AddRevocation(createRevInfo(testIA, 1, false))
	res := s.IsRevoked(createMockPath(ctrl, testIA, 2))
	assert.False(t, res)
	res = s.IsRevoked(createMockPath(ctrl, testIA, 1))
	assert.True(t, res)
	s.Cleanup()
}

func TestExpiredRevocation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := pathhealth.MemoryRevocationStore{}
	s.AddRevocation(createRevInfo(testIA, 1, true))
	res := s.IsRevoked(createMockPath(ctrl, testIA, 1))
	assert.False(t, res)
	s.Cleanup()
}

func createMockPath(ctrl *gomock.Controller, ia addr.IA, ifid common.IFIDType) snet.Path {
	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Metadata().Return(&snet.PathMetadata{
		Interfaces: []snet.PathInterface{{IA: ia, ID: ifid}},
	})
	return path
}

func createRevInfo(ia addr.IA, ifid common.IFIDType, expired bool) *path_mgmt.RevInfo {
	ri := &path_mgmt.RevInfo{
		RawIsdas: ia.IAInt(),
		IfID:     ifid,
		// Revocation was issued a minute ago.
		RawTimestamp: util.TimeToSecs(time.Now().Add(-time.Minute)),
	}
	// Revocation is valid for 1, respective 120 seconds.
	if expired {
		ri.RawTTL = 1
	} else {
		ri.RawTTL = 120
	}
	return ri
}
