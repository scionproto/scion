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

package grpc_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hpgrpc "github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath/grpc/mock_grpc"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/proto/hidden_segment"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
	"github.com/scionproto/scion/go/pkg/proto/hidden_segment/mock_hidden_segment"
)

func TestRegistererRegisterSegment(t *testing.T) {
	testCases := map[string]struct {
		input     hiddenpath.SegmentRegistration
		hpServer  func(*gomock.Controller) hidden_segment.HiddenSegmentRegistrationServiceServer
		signer    func(ctrl *gomock.Controller) hpgrpc.Signer
		regular   func(*gomock.Controller) beaconing.RPC
		assertErr assert.ErrorAssertionFunc
	}{
		"valid hidden": {
			hpServer: func(c *gomock.Controller) hspb.HiddenSegmentRegistrationServiceServer {
				s := mock_hidden_segment.NewMockHiddenSegmentRegistrationServiceServer(c)
				s.EXPECT().HiddenSegmentRegistration(gomock.Any(), gomock.Any()).
					Return(&hidden_segment.HiddenSegmentRegistrationResponse{}, nil)
				return s
			},
			signer: func(ctrl *gomock.Controller) hpgrpc.Signer {
				signer := mock_grpc.NewMockSigner(ctrl)
				signer.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&cryptopb.SignedMessage{}, nil)
				return signer
			},
			regular: func(ctrl *gomock.Controller) beaconing.RPC {
				r := mock_beaconing.NewMockRPC(ctrl)
				r.EXPECT().RegisterSegment(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				return r
			},
			input: hiddenpath.SegmentRegistration{
				GroupID: hiddenpath.GroupID{Suffix: 42},
				Seg:     createSeg(),
			},
			assertErr: assert.NoError,
		},
		"valid public": {
			hpServer: func(c *gomock.Controller) hspb.HiddenSegmentRegistrationServiceServer {
				s := mock_hidden_segment.NewMockHiddenSegmentRegistrationServiceServer(c)
				s.EXPECT().HiddenSegmentRegistration(gomock.Any(), gomock.Any()).
					Return(&hidden_segment.HiddenSegmentRegistrationResponse{}, nil).Times(0)
				return s
			},
			signer: func(ctrl *gomock.Controller) hpgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			regular: func(ctrl *gomock.Controller) beaconing.RPC {
				r := mock_beaconing.NewMockRPC(ctrl)
				r.EXPECT().RegisterSegment(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
				return r
			},
			input: hiddenpath.SegmentRegistration{
				Seg: createSeg(),
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			svc := xtest.NewGRPCService()
			hspb.RegisterHiddenSegmentRegistrationServiceServer(svc.Server(), tc.hpServer(ctrl))
			svc.Start(t)

			s := hpgrpc.Registerer{
				Dialer:              svc,
				RegularRegistration: tc.regular(ctrl),
				Signer:              tc.signer(ctrl),
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err := s.RegisterSegment(ctx, tc.input, &net.UDPAddr{})
			tc.assertErr(t, err)
		})
	}

}

func createSeg() seg.Meta {
	asEntry := seg.ASEntry{
		Local: xtest.MustParseIA("1-ff00:0:110"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: bytes.Repeat([]byte{0x11}, 6)},
		},
	}
	ps, _ := seg.CreateSegment(time.Now(), 1337)
	ps.AddASEntry(context.Background(), asEntry, graph.NewSigner())

	return seg.Meta{Type: seg.TypeDown, Segment: ps}
}
