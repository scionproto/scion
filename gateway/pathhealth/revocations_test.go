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
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
)

var (
	testIA addr.IA = addr.MustIAFrom(3, 4)
)

func TestEmptyStore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := pathhealth.MemoryRevocationStore{}
	res := s.IsRevoked(createMockPath(ctrl, testIA, 1))
	assert.False(t, res)
	s.Cleanup(context.Background())
}

func TestRevocation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := pathhealth.MemoryRevocationStore{}
	s.AddRevocation(context.Background(), createRevInfo(testIA, 1, false))
	res := s.IsRevoked(createMockPath(ctrl, testIA, 2))
	assert.False(t, res)
	res = s.IsRevoked(createMockPath(ctrl, testIA, 1))
	assert.True(t, res)
	s.Cleanup(context.Background())
}

func TestExpiredRevocation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := pathhealth.MemoryRevocationStore{}
	s.AddRevocation(context.Background(), createRevInfo(testIA, 1, true))
	res := s.IsRevoked(createMockPath(ctrl, testIA, 1))
	assert.False(t, res)
	s.Cleanup(context.Background())
}

func createMockPath(ctrl *gomock.Controller, ia addr.IA, ifID iface.ID) snet.Path {
	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Metadata().Return(&snet.PathMetadata{
		Interfaces: []snet.PathInterface{{IA: ia, ID: ifID}},
	})
	return path
}

func createRevInfo(ia addr.IA, ifID iface.ID, expired bool) *path_mgmt.RevInfo {
	ri := &path_mgmt.RevInfo{
		RawIsdas: ia,
		IfID:     ifID,
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
