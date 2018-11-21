// Copyright 2018 ETH Zurich
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

package pathsource

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	ErrNoResolver = "no resolver set"
	ErrNoPath     = "path not found"
	ErrInitPath   = "raw forwarding path offsets could not be initialized"
	ErrBadOverlay = "unable to extract next hop from sciond path entry"
)

// PathSource is a source of paths and overlay addresses for snet.
type PathSource interface {
	Get(ctx context.Context, src, dst addr.IA) (*overlay.OverlayAddr, *spath.Path, error)
}

type pathSource struct {
	resolver pathmgr.Resolver
}

// NewPathSource initializes a source of paths and overlay addresses for snet,
// with information obtained from resolver. Passing in a nil resolver is
// allowed, but the source will always return an error when invoked.
func NewPathSource(resolver pathmgr.Resolver) PathSource {
	return &pathSource{resolver: resolver}
}

func (ps *pathSource) Get(ctx context.Context,
	src, dst addr.IA) (*overlay.OverlayAddr, *spath.Path, error) {

	if ps.resolver == nil {
		return nil, nil, common.NewBasicError(ErrNoResolver, nil)
	}
	paths := ps.resolver.Query(ctx, src, dst)
	sciondPath := paths.GetAppPath("")
	if sciondPath == nil {
		return nil, nil, common.NewBasicError(ErrNoPath, nil)
	}
	path := &spath.Path{Raw: sciondPath.Entry.Path.FwdPath}
	if err := path.InitOffsets(); err != nil {
		return nil, nil, common.NewBasicError(ErrInitPath, nil)
	}
	overlayAddr, err := sciondPath.Entry.HostInfo.Overlay()
	if err != nil {
		return nil, nil, common.NewBasicError(ErrBadOverlay, nil)
	}
	return overlayAddr, path, nil
}
