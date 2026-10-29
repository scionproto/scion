// Copyright 2026 ETH Zurich
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

package endhost

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/combinator"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/revcache/memrevcache"
)

type PathService struct {
	client                   endhostconnect.SegmentsServiceClient
	trustService             *TrustService
	topo                     snet.Topology
	verificationUnsupported  bool
	localIA                  addr.IA
	revCache                 revcache.RevCache
	EndhostRevocationHandler *endhostRevocationHandler
	revCleaner               *periodic.Runner
}

type endhostRevocationHandler struct {
	revCache revcache.RevCache
}

func (e *endhostRevocationHandler) Revoke(ctx context.Context, revInfo *path_mgmt.RevInfo) error {
	_, err := e.revCache.Insert(ctx, revInfo)
	if err != nil {
		return err
	}
	return nil
}

func NewPathService(url string, topo snet.Topology, httpClient *http.Client, localIA addr.IA, trustService *TrustService) *PathService {
	revCache := memrevcache.New()
	p := &PathService{
		client:       endhostconnect.NewSegmentsServiceClient(httpClient, url),
		topo:         topo,
		trustService: trustService,
		localIA:      localIA,
		revCache:     revCache,
		EndhostRevocationHandler: &endhostRevocationHandler{
			revCache: revCache,
		},
		revCleaner: periodic.Start(revcache.NewCleaner(revCache, "endhost_revocation"), 10*time.Second, 10*time.Second),
	}
	return p
}
func (p *PathService) Close() error {
	if p.revCleaner != nil {
		p.revCleaner.Stop()
	}
	if p.revCache != nil {
		err := p.revCache.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type PathReqOption func(*pathReqOptions)
type pathReqOptions struct {
	disableVerifyPathSegments              bool
	numPaths                               uint32
	skipSegmentVerificationIfUnimplemented bool
}

func WithDisabledSegVerification() PathReqOption {
	return func(o *pathReqOptions) {
		o.disableVerifyPathSegments = true
	}
}

// WithNumberOfPaths sets the maximum number of paths to return.
// If the limit is not reached after requesting a page, further
// pages are requested.
func WithNumberOfPaths(n uint32) PathReqOption {
	return func(o *pathReqOptions) {
		o.numPaths = n
	}
}

// TODO: this option should entirely be removed once all ASes that support the endhost API also support the trust endpoint
func WithSkipSegmentVerificationIfUnsupportedByAS() PathReqOption {
	return func(o *pathReqOptions) {
		o.skipSegmentVerificationIfUnimplemented = true
	}
}

// Query exists to implement snet.PathQuerier and just calls the Path function without options.
func (s *PathService) Query(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return s.Paths(ctx, dst)
}

func (s *PathService) filterVerifiedSegments(ctx context.Context, up []*seg.PathSegment,
	core []*seg.PathSegment, down []*seg.PathSegment, options *pathReqOptions) (
	[]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, error) {

	verify := func(segments []*seg.PathSegment) ([]*seg.PathSegment, error) {
		if len(segments) == 0 {
			return segments, nil
		}
		verifiedSegments := make([]*seg.PathSegment, 0, len(segments))
		verificationErrors, err := s.trustService.VerifyPathSegments(ctx, segments)
		if err != nil {
			return nil, err
		}
		for i := range verificationErrors {
			if verificationErrors[i] != nil {
				log.Debug("Path segment filtered", "firstIA", segments[i].FirstIA(),
					"lastIA", segments[i].LastIA(), "err", verificationErrors[i])
			} else {
				verifiedSegments = append(verifiedSegments, segments[i])
			}
		}
		return verifiedSegments, nil
	}
	if s.trustService == nil {
		return nil, nil, nil, serrors.New("trust service not configured")
	}

	verifiedUp, err := verify(up)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			s.verificationUnsupported = true
		} else {
			return nil, nil, nil, err
		}
	}
	verifiedCore, err := verify(core)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			s.verificationUnsupported = true
		} else {
			return nil, nil, nil, err
		}
	}
	verifiedDown, err := verify(down)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			s.verificationUnsupported = true
		} else {
			return nil, nil, nil, err
		}
	}
	if s.verificationUnsupported {
		log.Debug("requested segment verification but unsupported by local AS")
		if options.skipSegmentVerificationIfUnimplemented {
			return up, core, down, nil
		} else {
			return up, core, down,
				serrors.New("requested segment verification but unsupported by local AS")
		}
	}
	return verifiedUp, verifiedCore, verifiedDown, nil
}

func (s *PathService) filterRevoked(ctx context.Context,
	paths []combinator.Path) []combinator.Path {

	logger := log.FromCtx(ctx)
	var newPaths []combinator.Path
	debugOn := logger.Enabled(log.DebugLevel)
	revokedInterfaces := make(map[snet.PathInterface]struct{})
	for _, path := range paths {
		revoked := false
		for _, iface := range path.Metadata.Interfaces {
			// cache automatically expires outdated revocations every second,
			// so a cache hit implies revocation is still active.
			rev, err := s.revCache.Get(ctx, revcache.NewKey(iface.IA, iface.ID))
			if err != nil {
				logger.Error("Failed to get revocation", "err", err)
				// continue, the client might still get some usable paths like this.
			}
			if rev != nil && debugOn {
				revokedInterfaces[snet.PathInterface{IA: iface.IA, ID: iface.ID}] = struct{}{}
			}
			revoked = revoked || rev != nil
		}
		if !revoked {
			newPaths = append(newPaths, path)
		}
	}
	if len(paths) != len(newPaths) {
		logger.Debug("Filtered paths with revocations",
			"num_paths", len(paths), "num_revoked_paths", len(paths)-len(newPaths),
			"revoked_due_to", revocationsString(revokedInterfaces))
	}
	return newPaths
}

func revocationsString(revocations map[snet.PathInterface]struct{}) string {
	r := make([]string, 0, len(revocations))
	for i := range revocations {
		r = append(r, i.String())
	}
	sort.Strings(r)
	return fmt.Sprint(r)
}

// Paths returns paths from the local IA to the destination IA.
// It asks for the corresponding path segments from the endhost API endpoint and combines them
// into end to end paths. The maximum number of paths returned can be configured via the
// WithNumberOfPaths options. Additionally, the VerifyPathSegments option can be used to filter
// out all path segments that fail verification.
func (s *PathService) Paths(ctx context.Context, dst addr.IA, opts ...PathReqOption) (
	[]snet.Path, error) {

	interfacesToString := func(elems []snet.PathInterface) string {
		parts := make([]string, len(elems))
		for i, e := range elems {
			parts[i] = e.String()
		}
		return strings.Join(parts, "|")
	}
	options := &pathReqOptions{}
	for _, opt := range opts {
		opt(options)
	}
	maxRequestedPaths := uint32(64)
	if options.numPaths != 0 {
		maxRequestedPaths = options.numPaths
	}
	paginator := s.newPaginator(dst, 64)
	paths := make([]snet.Path, 0, 64)
	seen := make(map[string]struct{})

	for len(paths) < int(maxRequestedPaths) && paginator.HasNext() {
		up, core, down, err := paginator.NextPage(ctx)
		metricListSegmentsTotal.Increment(err, "dst", dst.String())
		if err != nil {
			return nil, err
		}
		if !options.disableVerifyPathSegments && !s.verificationUnsupported {
			up, core, down, err = s.filterVerifiedSegments(ctx, up, core, down, options)
			if err != nil {
				return nil, err
			}
		}
		combinedPaths := combinator.Combine(s.localIA, dst, up, core, down, false)
		combinedPaths = s.filterRevoked(ctx, combinedPaths)
		for _, p := range combinedPaths {
			mapKey := interfacesToString(p.Metadata.Interfaces)
			if _, isSeen := seen[mapKey]; isSeen {
				continue
			}
			nextHopNetIpPort, ok := s.topo.Interface(uint16(p.Metadata.Interfaces[0].ID))
			if !ok {
				return nil, serrors.New("nexthop cannot be determined")
			}
			addr := nextHopNetIpPort.Addr()
			nextHop := &net.UDPAddr{
				IP:   addr.AsSlice(),
				Port: int(nextHopNetIpPort.Port()),
				Zone: addr.Zone(),
			}
			path := snetpath.Path{
				Src:           s.localIA,
				Dst:           dst,
				DataplanePath: p.SCIONPath,
				Meta:          p.Metadata,
				NextHop:       nextHop,
			}
			paths = append(paths, path)
			seen[mapKey] = struct{}{}
		}
	}
	if options.numPaths != 0 && len(paths) > int(options.numPaths) {
		return paths[:options.numPaths], nil
	}
	return paths, nil
}

type paginator struct {
	client       endhostconnect.SegmentsServiceClient
	pageSize     int32
	pageToken    string
	hasNext      bool
	src          addr.IA
	dst          addr.IA
	trustService *TrustService
}

func (s *PathService) newPaginator(dst addr.IA, pageSize int32) *paginator {
	return &paginator{
		client:       s.client,
		pageSize:     pageSize,
		pageToken:    "",
		hasNext:      true,
		src:          s.localIA,
		dst:          dst,
		trustService: s.trustService,
	}
}

func (s *paginator) HasNext() bool {
	return s.hasNext
}

func (s *paginator) NextPage(ctx context.Context) (
	[]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, error) {

	res, err := s.client.ListSegments(ctx, &connect.Request[endhost.ListSegmentsRequest]{
		Msg: &endhost.ListSegmentsRequest{
			SrcIsdAs:  uint64(s.src),
			DstIsdAs:  uint64(s.dst),
			PageSize:  s.pageSize,
			PageToken: s.pageToken,
		},
	})
	if err != nil {
		return nil, nil, nil, serrors.Wrap("on ListSegments", err)
	}
	s.pageToken = res.Msg.NextPageToken
	s.hasNext = s.pageToken != ""

	upSegments := make([]*seg.PathSegment, 0, len(res.Msg.UpSegments))
	coreSegments := make([]*seg.PathSegment, 0, len(res.Msg.CoreSegments))
	downSegments := make([]*seg.PathSegment, 0, len(res.Msg.DownSegments))
	for _, pb := range res.Msg.UpSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		upSegments = append(upSegments, ps)
	}
	for _, pb := range res.Msg.CoreSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		coreSegments = append(coreSegments, ps)
	}
	for _, pb := range res.Msg.DownSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		downSegments = append(downSegments, ps)
	}
	return upSegments, coreSegments, downSegments, nil
}
