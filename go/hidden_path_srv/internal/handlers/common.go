// Copyright 2019 ETH Zurich
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

package handlers

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hpsegreq"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	HandlerTimeout = 30 * time.Second

	NoSegmentsErr = "No segments"
)

// HandlerArgs are the values required to create the hidden path server's handlers.
type HandlerArgs struct {
	HiddenPathDB    hiddenpathdb.HiddenPathDB
	Groups          map[hiddenpath.GroupId]*hiddenpath.Group
	LocalIA         addr.IA
	VerifierFactory infra.VerificationFactory
}

type baseHandler struct {
	request         *infra.Request
	hpDB            hiddenpathdb.HiddenPathDB
	groups          map[hiddenpath.GroupId]*hiddenpath.Group
	localIA         addr.IA
	verifierFactory infra.VerificationFactory
}

func newBaseHandler(request *infra.Request, args HandlerArgs) *baseHandler {
	return &baseHandler{
		request:         request,
		hpDB:            args.HiddenPathDB,
		groups:          args.Groups,
		localIA:         args.LocalIA,
		verifierFactory: args.VerifierFactory,
	}
}

func (h *baseHandler) verifyAndStore(ctx context.Context, src net.Addr,
	hpSegReg *path_mgmt.HPSegReg) error {

	logger := log.FromCtx(ctx)

	// check HPGroup related permissions
	groupId := hiddenpath.IdFromMsg(hpSegReg.GroupId)
	if err := h.checkGroupPermissions(groupId, true); err != nil {
		return common.NewBasicError("Group configuration error", err)
	}
	// verify and store the segments
	var insertedSegmentIDs []string
	var mtx sync.Mutex
	verifiedSegs := make([]*seg.Meta, 0, len(hpSegReg.Recs))
	verifiedSeg := func(ctx context.Context, s *seg.Meta) {
		mtx.Lock()
		defer mtx.Unlock()
		verifiedSegs = append(verifiedSegs, s)
	}
	segErr := func(s *seg.Meta, err error) {
		logger.Warn("Segment verification failed", "segment", s.Segment, "err", err)
	}
	segverifier.Verify(ctx, h.verifierFactory.NewVerifier(), src, hpSegReg.Recs, nil, verifiedSeg,
		nil, segErr, nil)

	// Return early if we have nothing to insert.
	if len(verifiedSegs) == 0 {
		return common.NewBasicError(NoSegmentsErr, nil)
	}
	tx, err := h.hpDB.BeginTransaction(ctx, nil)
	if err != nil {
		return err
	}
	// sort to prevent sql deadlock
	sort.Slice(verifiedSegs, func(i, j int) bool {
		return verifiedSegs[i].Segment.GetLoggingID() < verifiedSegs[j].Segment.GetLoggingID()
	})
	for _, s := range verifiedSegs {
		// Make sure segment is marked as hidden
		if !checkHiddenSegExtn(s) {
			return common.NewBasicError("Unable to insert segment into path database:"+
				"Missing HiddenPathSeg extension", nil, "seg", s.Segment)
		}
		n, err := tx.Insert(ctx, s, hpsegreq.GroupIdsToSet(groupId))
		if err != nil {
			if errRollback := tx.Rollback(); errRollback != nil {
				err = common.NewBasicError("Unable to rollback", err, "rollbackErr", errRollback)
			}
			return common.NewBasicError("Unable to insert segment into path database", err,
				"seg", s.Segment)
		}
		if wasInserted := n > 0; wasInserted {
			insertedSegmentIDs = append(insertedSegmentIDs, s.Segment.GetLoggingID())
		}
	}
	err = tx.Commit()
	if err != nil {
		return common.NewBasicError("Failed to commit transaction", err)
	}
	if len(insertedSegmentIDs) > 0 {
		logger.Debug("Hidden segments inserted in DB", "count", len(insertedSegmentIDs),
			"segments", insertedSegmentIDs)
	}

	return nil
}

func (h *baseHandler) checkGroupPermissions(groupId hiddenpath.GroupId, write bool) error {
	group, ok := h.groups[groupId]
	if !ok {
		return common.NewBasicError("Group not known to HPS", nil, "group", groupId)
	}
	if !group.HasRegistry(h.localIA) {
		return common.NewBasicError("HPS is not a Registry of this group",
			nil, "group", groupId)
	}
	peer, ok := h.request.Peer.(*snet.Addr)
	if !ok {
		// TODO: Can this ever fail?
	}
	if group.Owner == peer.IA {
		return nil
	}
	if write {
		if !group.HasWriter(peer.IA) {
			return common.NewBasicError("Peer is not a writer of this group",
				nil, "group", groupId)
		}
		return nil
	}
	if !group.HasReader(peer.IA) {
		return common.NewBasicError("Peer is not a reader of this group",
			nil, "group", groupId)
	}
	return nil
}

func checkHiddenSegExtn(s *seg.Meta) bool {
	numEntries := len(s.Segment.ASEntries)
	if numEntries < 1 {
		return false
	}
	lastASEntry := s.Segment.ASEntries[numEntries-1]
	return lastASEntry.Exts.HiddenPathSeg.Set
}
