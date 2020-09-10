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

package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// IfStateConsumerServer implements InterfaceStateConsumerService.
type IfStateConsumerServer struct {
	Handler IfStateHandler
}

func (s IfStateConsumerServer) InterfaceStateConsume(ctx context.Context,
	request *cppb.InterfaceStateConsumeRequest) (*cppb.InterfaceStateConsumeResponse, error) {

	states := make([]InterfaceState, 0, len(request.States))
	for _, s := range request.States {
		var rev *path_mgmt.SignedRevInfo
		if len(s.SignedRev) > 0 {
			var err error
			rev, err = path_mgmt.NewSignedRevInfoFromRaw(s.SignedRev)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, "revocation malformed")
			}
		}
		states = append(states, InterfaceState{ID: s.Id, Revocation: rev})
	}
	s.Handler.UpdateState(states)
	return &cppb.InterfaceStateConsumeResponse{}, nil
}
