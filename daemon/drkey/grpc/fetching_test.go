// Copyright 2022 ETH Zurich
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

package grpc_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"

	sd_drkey "github.com/scionproto/scion/daemon/drkey"
	sd_grpc "github.com/scionproto/scion/daemon/drkey/grpc"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	mock_cppb "github.com/scionproto/scion/pkg/proto/control_plane/mock_control_plane"
)

var _ sd_drkey.Fetcher = (*sd_grpc.Fetcher)(nil)

func TestGetHostHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	now := time.Now().UTC()
	epochBegin, err := ptypes.TimestampProto(now)
	require.NoError(t, err)
	epochEnd, err := ptypes.TimestampProto(now.Add(24 * time.Hour))
	require.NoError(t, err)

	resp := &cppb.DRKeyHostHostResponse{
		Key:        xtest.MustParseHexString("c584cad32613547c64823c756651b6f5"),
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
	}

	daemonSrv := mock_cppb.NewMockDRKeyIntraServiceServer(ctrl)
	daemonSrv.EXPECT().DRKeyHostHost(gomock.Any(),
		gomock.Any()).Return(
		resp,
		nil,
	)

	server := xtest.NewGRPCService()
	cppb.RegisterDRKeyIntraServiceServer(server.Server(), daemonSrv)
	server.Start(t)

	fetcher := sd_grpc.Fetcher{
		Dialer: server,
	}

	meta := drkey.HostHostMeta{}
	_, err = fetcher.HostHostKey(context.Background(), meta)
	require.NoError(t, err)
}
