// Copyright 2019 Anapaya Systems
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

package segreq

import (
	"context"
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

// CoreChecker checks whether a given ia is core.
type CoreChecker struct {
	Inspector infra.ASInspector
}

func (c *CoreChecker) IsCore(ctx context.Context, ia addr.IA) (bool, error) {
	if ia.IsWildcard() {
		return true, nil
	}
	return c.Inspector.HasAttributes(ctx, ia, infra.ASInspectorOpts{
		RequiredAttributes: []infra.Attribute{infra.Core},
	})
}

func segsToRecs(ctx context.Context, segs segfetcher.Segments) []*seg.Meta {
	logger := log.FromCtx(ctx)
	recs := make([]*seg.Meta, 0, len(segs.Up)+len(segs.Core)+len(segs.Down))
	for _, s := range segs.Up {
		logger.Trace(fmt.Sprintf("[segReqHandler:collectSegs] up %v -> %v",
			s.FirstIA(), s.LastIA()), "seg", s.GetLoggingID())
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_up))
	}
	for _, s := range segs.Core {
		logger.Trace(fmt.Sprintf("[segReqHandler:collectSegs] core %v -> %v",
			s.FirstIA(), s.LastIA()), "seg", s.GetLoggingID())
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_core))
	}
	for _, s := range segs.Down {
		logger.Trace(fmt.Sprintf("[segReqHandler:collectSegs] down %v -> %v",
			s.FirstIA(), s.LastIA()), "seg", s.GetLoggingID())
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_down))
	}
	return recs
}
