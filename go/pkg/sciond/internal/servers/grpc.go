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

package servers

import (
	"context"
	"time"

	timestamppb "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	sdpb "github.com/scionproto/scion/go/pkg/proto/daemon"
	"github.com/scionproto/scion/go/pkg/sciond/fetcher"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

// DaemonServer handles gRPC requests to the SCION daemon.
type DaemonServer struct {
	Fetcher      fetcher.Fetcher
	TopoProvider topology.Provider
	RevCache     revcache.RevCache
	ASInspector  trust.Inspector

	Metrics Metrics
}

// Paths serves the paths request.
func (s DaemonServer) Paths(ctx context.Context,
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

	start := time.Now()
	dstI := addr.IAInt(req.DestinationIsdAs).IA().I
	response, err := s.paths(ctx, req)
	s.Metrics.PathsRequests.inc(
		pathReqLabels{Result: errToMetricResult(err), Dst: dstI},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s DaemonServer) paths(ctx context.Context,
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

	if _, ok := ctx.Deadline(); !ok {
		var cancelF context.CancelFunc
		ctx, cancelF = context.WithTimeout(ctx, 10*time.Second)
		defer cancelF()
	}
	srcIA, dstIA := addr.IAInt(req.SourceIsdAs).IA(), addr.IAInt(req.DestinationIsdAs).IA()
	go func() {
		defer log.HandlePanic()
		s.backgroundPaths(ctx, srcIA, dstIA, req.Refresh)
	}()
	paths, err := s.Fetcher.GetPaths(ctx, srcIA, dstIA, req.Refresh)
	if err != nil {
		log.FromCtx(ctx).Debug("Fetching paths", "err", err,
			"src", srcIA, "dst", dstIA, "refresh", req.Refresh)
		return nil, err
	}
	reply := &sdpb.PathsResponse{}
	for _, p := range paths {
		var interfaces []*sdpb.PathInterface
		for _, intf := range p.Interfaces() {
			interfaces = append(interfaces, &sdpb.PathInterface{
				Id:    uint64(intf.ID),
				IsdAs: uint64(intf.IA.IAInt()),
			})
		}

		var raw []byte
		if spath := p.Path(); spath != nil {
			raw = spath.Raw
		}
		nextHopStr := ""
		if nextHop := p.UnderlayNextHop(); nextHop != nil {
			nextHopStr = nextHop.String()
		}
		reply.Paths = append(reply.Paths, &sdpb.Path{
			Raw: raw,
			Interface: &sdpb.Interface{
				Address: &sdpb.Underlay{Address: nextHopStr},
			},
			Interfaces: interfaces,
			Mtu:        uint32(p.Metadata().MTU()),
			Expiration: &timestamppb.Timestamp{Seconds: p.Metadata().Expiry().Unix()},
			HeaderV2:   true,
		})
	}
	return reply, nil
}

func (s DaemonServer) backgroundPaths(origCtx context.Context, src, dst addr.IA, refresh bool) {
	backgroundTimeout := 5 * time.Second
	deadline, ok := origCtx.Deadline()
	if !ok || time.Until(deadline) > backgroundTimeout {
		// the original context is large enough no need to spin a background fetch.
		return
	}
	ctx, cancelF := context.WithTimeout(context.Background(), backgroundTimeout)
	defer cancelF()
	var spanOpts []opentracing.StartSpanOption
	if span := opentracing.SpanFromContext(origCtx); span != nil {
		spanOpts = append(spanOpts, opentracing.FollowsFrom(span.Context()))
	}
	span, ctx := opentracing.StartSpanFromContext(ctx, "fetch.paths.backround", spanOpts...)
	defer span.Finish()
	_, err := s.Fetcher.GetPaths(ctx, src, dst, refresh)
	if err != nil {
		log.FromCtx(ctx).Debug("Error fetching paths", "err", err,
			"src", src, "dst", dst, "refresh", refresh)
	}
}

// AS serves the AS request.
func (s DaemonServer) AS(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	start := time.Now()
	response, err := s.as(ctx, req)
	s.Metrics.ASRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s DaemonServer) as(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	topo := s.TopoProvider.Get()
	reqIA := addr.IAInt(req.IsdAs).IA()
	if reqIA.IsZero() {
		reqIA = topo.IA()
	}
	mtu := uint32(0)
	if reqIA.Equal(topo.IA()) {
		mtu = uint32(topo.MTU())
	}
	core, err := s.ASInspector.HasAttributes(ctx, reqIA, trust.Core)
	if err != nil {
		log.FromCtx(ctx).Error("Inspecting ISD-AS", "err", err, "isd_as", reqIA)
		return nil, serrors.WrapStr("inspecting ISD-AS", err, "isd_as", reqIA)
	}
	reply := &sdpb.ASResponse{
		IsdAs: uint64(reqIA.IAInt()),
		Core:  core,
		Mtu:   mtu,
	}
	return reply, nil
}

// Interfaces serves the interfaces request.
func (s DaemonServer) Interfaces(ctx context.Context,
	req *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	start := time.Now()
	response, err := s.interfaces(ctx, req)
	s.Metrics.InterfacesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s DaemonServer) interfaces(ctx context.Context,
	_ *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	reply := &sdpb.InterfacesResponse{
		Interfaces: make(map[uint64]*sdpb.Interface),
	}
	topo := s.TopoProvider.Get()
	for _, ifID := range topo.InterfaceIDs() {
		nextHop, ok := topo.UnderlayNextHop(ifID)
		if !ok {
			continue
		}
		reply.Interfaces[uint64(ifID)] = &sdpb.Interface{
			Address: &sdpb.Underlay{
				Address: nextHop.String(),
			},
		}
	}
	return reply, nil
}

// Services serves the services request.
func (s DaemonServer) Services(ctx context.Context,
	req *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	start := time.Now()
	respsonse, err := s.services(ctx, req)
	s.Metrics.ServicesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return respsonse, unwrapMetricsError(err)
}

func (s DaemonServer) services(ctx context.Context,
	_ *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	reply := &sdpb.ServicesResponse{
		Services: make(map[string]*sdpb.ListService),
	}
	topo := s.TopoProvider.Get()
	serviceTypes := []proto.ServiceType{proto.ServiceType_bs, proto.ServiceType_cs,
		proto.ServiceType_ps, proto.ServiceType_sig}
	for _, t := range serviceTypes {
		list := &sdpb.ListService{}
		svcHosts := topo.MakeHostInfos(t)
		for _, h := range svcHosts {
			// TODO(lukedirtwalker): build actual URI after it's defined (anapapaya/scion#3587)
			list.Services = append(list.Services, &sdpb.Service{Uri: h.String()})
		}
		reply.Services[t.String()] = list
	}
	return reply, nil
}

// NotifyInterfaceDown notifies the server about an interface that is down.
func (s DaemonServer) NotifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	start := time.Now()
	response, err := s.notifyInterfaceDown(ctx, req)
	s.Metrics.InterfaceDownNotifications.inc(
		ifDownLabels{Result: errToMetricResult(err), Src: "notification"},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s DaemonServer) notifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	revInfo := &path_mgmt.RevInfo{
		RawIsdas:     addr.IAInt(req.IsdAs),
		IfID:         common.IFIDType(req.Id),
		LinkType:     proto.LinkType_core,
		RawTTL:       10,
		RawTimestamp: util.TimeToSecs(time.Now()),
	}
	sRev, err := path_mgmt.NewSignedRevInfo(revInfo, infra.NullSigner)
	if err != nil {
		log.FromCtx(ctx).Error("Signing revocation", "err", err, "req", req)
		return nil, metricsError{
			err:    serrors.WrapStr("signing revocation", err),
			result: prom.ErrInternal,
		}
	}
	_, err = s.RevCache.Insert(ctx, sRev)
	if err != nil {
		log.FromCtx(ctx).Error("Inserting revocation", "err", err, "req", req)
		return nil, metricsError{
			err:    serrors.WrapStr("inserting revocation", err),
			result: prom.ErrDB,
		}
	}
	return &sdpb.NotifyInterfaceDownResponse{}, nil
}
