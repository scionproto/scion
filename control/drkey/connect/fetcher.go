// Copyright 2025 SCION Association, Anapaya Systems
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

package connect

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"

	"github.com/scionproto/scion/control/drkey/grpc"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
)

const (
	// defaultRPCDialTimeout is the timeout used for dialing the gRPC ClientConn.
	// This is shorter than the typical context deadline for the request.
	// Having a separate, more aggressive timeout for dialing allows to abort
	// quickly. This allows the surrounding infrastructure to retry quickly -- in
	// the case where this request goes over SCION/QUIC, retries are used to
	// route around broken paths.
	// This timeout needs to be long enough to allow for service address
	// resolution and the QUIC handshake to complete (two roundtrips).
	defaultRPCDialTimeout time.Duration = 2 * time.Second
)

var errNotReachable = serrors.New("remote not reachable")

// Fetcher obtains Level1 DRKey from a remote CS.
type Fetcher struct {
	// Dialer dials a new QUIC connection.
	Dialer     libconnect.Dialer
	Router     snet.Router
	MaxRetries int

	once       sync.Once
	errorPaths map[snet.PathFingerprint]struct{}
}

// Level1 queries a CS for a level 1 key.
func (f *Fetcher) Level1(
	ctx context.Context,
	meta drkey.Level1Meta,
) (drkey.Level1Key, error) {
	f.init()

	req := grpc.Level1MetaToProtoRequest(meta)

	// Keep retrying until the reaching MaxRetries.
	// getLevel1Key will use different paths out of Router retrieved paths.
	// These retries allow to route around broken paths.
	// Note: this is a temporary solution. In the future, this should be handled
	// by using longer lived grpc connections over different paths and thereby
	// explicitly keeping track of the path health.
	var errList serrors.List
	clear(f.errorPaths)
	for i := 0; i < f.MaxRetries; i++ {
		rep, err := f.getLevel1Key(ctx, meta.SrcIA, req)
		if errors.Is(err, errNotReachable) {
			return drkey.Level1Key{}, serrors.New(
				"level1 fetch failed",
				"try", i+1,
				"peer", meta.SrcIA,
				"err", err,
			)
		}
		if err == nil {
			lvl1Key, err := grpc.GetLevel1KeyFromReply(meta, rep)
			if err != nil {
				return drkey.Level1Key{}, serrors.Wrap("obtaining level 1 key from reply", err)
			}
			return lvl1Key, nil
		}
		errList = append(errList,
			serrors.Wrap("fetching level1", err, "try", i+1, "peer", meta.SrcIA),
		)
	}
	return drkey.Level1Key{}, serrors.Wrap(
		"reached max retry attempts fetching level1 key",
		errList)

}

func (f *Fetcher) getLevel1Key(
	ctx context.Context,
	srcIA addr.IA,
	req *cppb.DRKeyLevel1Request,
) (*cppb.DRKeyLevel1Response, error) {

	path, err := f.pathToDst(ctx, srcIA)
	if err != nil {
		return nil, err
	}
	remote := &snet.SVCAddr{
		IA:      srcIA,
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}
	dialer := f.Dialer(remote, squic.WithDialTimeout(defaultRPCDialTimeout))
	client := control_planeconnect.NewDRKeyInterServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.Transport{
				Dial: dialer.DialEarly,
			},
		},
		libconnect.BaseUrl(remote),
	)
	rep, err := client.DRKeyLevel1(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, serrors.Wrap("requesting level 1 key", err)
	}

	return rep.Msg, nil
}

func (f *Fetcher) pathToDst(ctx context.Context, dst addr.IA) (snet.Path, error) {
	paths, err := f.Router.AllRoutes(ctx, dst)
	if err != nil {
		return nil, serrors.JoinNoStack(errNotReachable, err)
	}
	if len(paths) == 0 {
		return nil, errNotReachable
	}
	for _, p := range paths {
		fp := p.Metadata().Fingerprint()
		if _, ok := f.errorPaths[fp]; ok {
			continue
		}
		f.errorPaths[fp] = struct{}{}
		return p, nil
	}
	// we've tried out all the paths; we reset the map to retry them.
	clear(f.errorPaths)
	return paths[0], nil
}

func (f *Fetcher) init() {
	f.once.Do(func() {
		f.errorPaths = make(map[snet.PathFingerprint]struct{})
	})
}
