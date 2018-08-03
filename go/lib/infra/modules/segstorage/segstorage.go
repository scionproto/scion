// Copyright 2018 Anapaya Systems
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

package segstorage

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/conn"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/proto"
)

type SegStorage struct {
	conn     conn.Conn
	revcache revcache.RevCache
	log      log.Logger
}

// New creates a SegStorage from the given conn and revcache.
// The log is used during operations on the segstorage.
func New(conn conn.Conn, revcache revcache.RevCache, log log.Logger) *SegStorage {
	return &SegStorage{
		conn:     conn,
		revcache: revcache,
		log:      log,
	}
}

// VerifyAndStore verifies recs and revInfos and stores them in the SegStorage.
func (s *SegStorage) VerifyAndStore(ctx context.Context,
	recs []*seg.Meta, revInfos []*path_mgmt.SignedRevInfo) error {
	units := segverifier.BuildUnits(recs, revInfos)
	unitResultsC := make(chan segverifier.UnitResult, len(units))
	for _, unit := range units {
		go unit.Verify(ctx, unitResultsC)
	}
Loop:
	for numResults := 0; numResults < len(units); numResults++ {
		select {
		case result := <-unitResultsC:
			if err, ok := result.Errors[-1]; ok {
				s.log.Info("Segment verification failed",
					"segment", result.Unit.SegMeta.Segment, "err", err)
			} else {
				// Verification succeeded
				n, err := s.conn.Insert(ctx, &result.Unit.SegMeta.Segment,
					[]proto.PathSegType{result.Unit.SegMeta.Type})
				if err != nil {
					s.log.Warn("Unable to insert segment into path database",
						"segment", result.Unit.SegMeta.Segment, "err", err)
					return err
				}
				if n > 0 {
					s.log.Debug("Inserted segment into path database",
						"segment", result.Unit.SegMeta.Segment)
				}
			}
			// Insert successfully verified revocations into the revcache
			for index, revocation := range result.Unit.SRevInfos {
				if err, ok := result.Errors[index]; ok {
					s.log.Info("Revocation verification failed",
						"revocation", revocation, "err", err)
				} else {
					// Verification succeeded for this revocation, so we can add it to the cache
					info, err := revocation.RevInfo()
					if err != nil {
						// This should be caught during network message sanitization
						panic(err)
					}
					s.revcache.Set(
						revcache.NewKey(info.IA(), common.IFIDType(info.IfID)),
						revocation,
						info.RelativeTTL(time.Now()),
					)
				}
			}
		case <-ctx.Done():
			break Loop
		}
	}
	return nil
}
