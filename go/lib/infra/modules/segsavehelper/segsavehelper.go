// Copyright 2018 ETH Zurich, Anapaya Systems
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

package segsavehelper

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

// VerifyAndStore verifies recs and revInfos and stores them in the SegStorage.
func VerifyAndStore(ctx context.Context,
	conn conn.Conn, rcache revcache.RevCache, log log.Logger,
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
				log.Info("Segment verification failed",
					"segment", result.Unit.SegMeta.Segment, "err", err)
			} else {
				// Verification succeeded
				n, err := conn.Insert(ctx, &result.Unit.SegMeta.Segment,
					[]proto.PathSegType{result.Unit.SegMeta.Type})
				if err != nil {
					log.Warn("Unable to insert segment into path database",
						"segment", result.Unit.SegMeta.Segment, "err", err)
					return err
				}
				if n > 0 {
					log.Debug("Inserted segment into path database",
						"segment", result.Unit.SegMeta.Segment)
				}
			}
			// Insert successfully verified revocations into the revcache
			for index, revocation := range result.Unit.SRevInfos {
				if err, ok := result.Errors[index]; ok {
					log.Info("Revocation verification failed",
						"revocation", revocation, "err", err)
				} else {
					// Verification succeeded for this revocation, so we can add it to the cache
					info, err := revocation.RevInfo()
					if err != nil {
						// This should be caught during network message sanitization
						panic(err)
					}
					rcache.Set(
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
