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

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// Store is the store in which to save the revocations.
type Store interface {
	InsertRevocations(ctx context.Context, verifiedRevs ...*path_mgmt.SignedRevInfo) error
}

// InterfaceStateServer implements the InterfaceStateService.
type InterfaceStateServer struct {
	Interfaces *ifstate.Interfaces

	RevCache revcache.RevCache
	RevStore Store
}

// SignedRevocation handles a signed revocation and inserts it into the revcache
// and store.
func (s InterfaceStateServer) SignedRevocation(ctx context.Context,
	request *cppb.SignedRevocationRequest) (*cppb.SignedRevocationResponse, error) {

	logger := log.FromCtx(ctx)
	logger.Debug("Received revocation")
	signedRevocation, err := path_mgmt.NewSignedRevInfoFromRaw(request.Raw)
	if err != nil {
		logger.Debug("Failed to parse revocation", "err", err)
		return nil, serrors.WrapStr("parsing", err)
	}
	if _, err := signedRevocation.RevInfo(); err != nil {
		logger.Debug("Failed to extract revocation", "err", err)
		return nil, serrors.WrapStr("extracting revocation info", err)
	}
	var errors serrors.List
	if _, err := s.RevCache.Insert(ctx, signedRevocation); err != nil {
		logger.Debug("Failed to insert revocation into revcache", "err", err)
		errors = append(errors, serrors.WrapStr("inserting in revcache", err))
	}
	if err := s.RevStore.InsertRevocations(ctx, signedRevocation); err != nil {
		logger.Debug("Failed to insert revocation into revocation store", "err", err)
		errors = append(errors, serrors.WrapStr("inserting in revstore", err))
	}
	if err := errors.ToError(); err != nil {
		return nil, err
	}
	return &cppb.SignedRevocationResponse{}, nil
}

// InterfaceState handles interface state requests.
func (s InterfaceStateServer) InterfaceState(ctx context.Context,
	request *cppb.InterfaceStateRequest) (*cppb.InterfaceStateResponse, error) {

	logger := log.FromCtx(ctx)
	logger.Debug("Received interface state request")
	all := s.Interfaces.All()
	states := make([]*cppb.InterfaceState, 0, len(all))
	for ifid, intf := range all {
		var rawRev []byte
		if rev := intf.Revocation(); rev != nil {
			var err error
			rawRev, err = rev.Pack()
			if err != nil {
				logger.Debug("Failed to pack revocation", "err", err)
				return nil, serrors.WrapStr("packing revocation", err, "ifid", ifid)
			}
		}
		log.Debug("state", "id", ifid, "rev", len(rawRev) > 0)
		states = append(states, &cppb.InterfaceState{Id: uint64(ifid), SignedRev: rawRev})
	}
	return &cppb.InterfaceStateResponse{States: states}, nil
}
