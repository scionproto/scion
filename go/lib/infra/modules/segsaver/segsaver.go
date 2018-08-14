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

// Package segsaver contains helper methods to save segments and revocations.
package segsaver

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/conn"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/proto"
)

// StoreSeg saves s to the given pdbconn. In case of failure the error is returned.
func StoreSeg(ctx context.Context, s *seg.Meta, pdbconn conn.Conn, log log.Logger) error {
	n, err := pdbconn.Insert(ctx, &s.Segment, []proto.PathSegType{s.Type})
	if err != nil {
		return err
	}
	if n > 0 {
		log.Debug("Inserted segment into path database", "segment", s.Segment)
	}
	return nil
}

// StoreRevocation stores a revocation in the revcache.
// Revocation must be verified before calling this.
func StoreRevocation(revocation *path_mgmt.SignedRevInfo, rcache revcache.RevCache) {
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
