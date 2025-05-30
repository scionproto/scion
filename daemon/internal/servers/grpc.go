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
	"fmt"
	"net"
	"time"

	"github.com/opentracing/opentracing-go"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	drkey_daemon "github.com/scionproto/scion/daemon/drkey"
	"github.com/scionproto/scion/daemon/fetcher"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

type Topology interface {
	IfIDs() []uint16
	UnderlayNextHop(uint16) *net.UDPAddr
	ControlServiceAddresses() []*net.UDPAddr
	PortRange() (uint16, uint16)
}

// DaemonServer handles gRPC requests to the SCION daemon.
type DaemonServer struct {
	IA          addr.IA
	MTU         uint16
	Topology    Topology
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	ASInspector trust.Inspector
	DRKeyClient *drkey_daemon.ClientEngine

	Metrics Metrics

	foregroundPathDedupe singleflight.Group
	backgroundPathDedupe singleflight.Group
}

// Paths serves the paths request.
func (s *DaemonServer) Paths(ctx context.Context,
	req *daemon.PathsRequest,
) (*daemon.PathsResponse, error) {
	start := time.Now()
	dstI := addr.IA(req.DestinationIsdAs).ISD()
	response, err := s.paths(ctx, req)
	s.Metrics.PathsRequests.inc(
		pathReqLabels{Result: errToMetricResult(err), Dst: dstI},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) paths(ctx context.Context,
	req *daemon.PathsRequest,
) (*daemon.PathsResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancelF context.CancelFunc
		ctx, cancelF = context.WithTimeout(ctx, 10*time.Second)
		defer cancelF()
	}
	srcIA, dstIA := addr.IA(req.SourceIsdAs), addr.IA(req.DestinationIsdAs)
	go func() {
		defer log.HandlePanic()
		s.backgroundPaths(ctx, srcIA, dstIA, req.Refresh)
	}()
	paths, err := s.fetchPaths(ctx, &s.foregroundPathDedupe, srcIA, dstIA, req.Refresh)
	if err != nil {
		log.FromCtx(ctx).Debug("Fetching paths", "err", err,
			"src", srcIA, "dst", dstIA, "refresh", req.Refresh)
		return nil, err
	}
	reply := &daemon.PathsResponse{}
	for _, p := range paths {
		reply.Paths = append(reply.Paths, pathToPB(p))
	}
	return reply, nil
}

func (s *DaemonServer) fetchPaths(
	ctx context.Context,
	group *singleflight.Group,
	src, dst addr.IA,
	refresh bool,
) ([]snet.Path, error) {
	r, err, _ := group.Do(fmt.Sprintf("%s%s%t", src, dst, refresh),
		func() (any, error) {
			return s.Fetcher.GetPaths(ctx, src, dst, refresh)
		},
	)
	// just cast to the correct type, ignore the "ok", since that can only be
	// false in case of a nil result.
	paths, _ := r.([]snet.Path)
	return paths, err
}

func pathToPB(path snet.Path) *daemon.Path {
	meta := path.Metadata()
	interfaces := make([]*daemon.PathInterface, len(meta.Interfaces))
	for i, intf := range meta.Interfaces {
		interfaces[i] = &daemon.PathInterface{
			Id:    uint64(intf.ID),
			IsdAs: uint64(intf.IA),
		}
	}

	latency := make([]*durationpb.Duration, len(meta.Latency))
	for i, v := range meta.Latency {
		seconds := int64(v / time.Second)
		nanos := int32(v - time.Duration(seconds)*time.Second)
		latency[i] = &durationpb.Duration{Seconds: seconds, Nanos: nanos}
	}
	geo := make([]*daemon.GeoCoordinates, len(meta.Geo))
	for i, v := range meta.Geo {
		geo[i] = &daemon.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]daemon.LinkType, len(meta.LinkType))
	for i, v := range meta.LinkType {
		linkType[i] = linkTypeToPB(v)
	}

	var raw []byte
	scionPath, ok := path.Dataplane().(snetpath.SCION)
	if ok {
		raw = scionPath.Raw
	}
	nextHopStr := ""
	if nextHop := path.UnderlayNextHop(); nextHop != nil {
		nextHopStr = nextHop.String()
	}

	epicAuths := &daemon.EpicAuths{
		AuthPhvf: append([]byte(nil), meta.EpicAuths.AuthPHVF...),
		AuthLhvf: append([]byte(nil), meta.EpicAuths.AuthLHVF...),
	}

	return &daemon.Path{
		Raw: raw,
		Interface: &daemon.Interface{
			Address: &daemon.Underlay{Address: nextHopStr},
		},
		Interfaces:   interfaces,
		Mtu:          uint32(meta.MTU),
		Expiration:   &timestamppb.Timestamp{Seconds: meta.Expiry.Unix()},
		Latency:      latency,
		Bandwidth:    meta.Bandwidth,
		Geo:          geo,
		LinkType:     linkType,
		InternalHops: meta.InternalHops,
		Notes:        meta.Notes,
		EpicAuths:    epicAuths,
	}
}

func linkTypeToPB(lt snet.LinkType) daemon.LinkType {
	switch lt {
	case snet.LinkTypeDirect:
		return daemon.LinkType_LINK_TYPE_DIRECT
	case snet.LinkTypeMultihop:
		return daemon.LinkType_LINK_TYPE_MULTI_HOP
	case snet.LinkTypeOpennet:
		return daemon.LinkType_LINK_TYPE_OPEN_NET
	default:
		return daemon.LinkType_LINK_TYPE_UNSPECIFIED
	}
}

func (s *DaemonServer) backgroundPaths(origCtx context.Context, src, dst addr.IA, refresh bool) {
	backgroundTimeout := 5 * time.Second
	deadline, ok := origCtx.Deadline()
	if !ok || time.Until(deadline) > backgroundTimeout {
		// the original context is large enough no need to spin a background fetch.
		return
	}
	// We're not passing origCtx because this is a background fetch that
	// should continue even in case origCtx is cancelled.
	ctx, cancelF := context.WithTimeout(context.Background(), backgroundTimeout)
	defer cancelF()
	var spanOpts []opentracing.StartSpanOption
	if span := opentracing.SpanFromContext(origCtx); span != nil {
		spanOpts = append(spanOpts, opentracing.FollowsFrom(span.Context()))
	}
	span, ctx := opentracing.StartSpanFromContext(ctx, "fetch.paths.background", spanOpts...)
	defer span.Finish()
	//nolint:contextcheck // false positive.
	if _, err := s.fetchPaths(ctx, &s.backgroundPathDedupe, src, dst, refresh); err != nil {
		log.FromCtx(ctx).Debug("Error fetching paths (background)", "err", err,
			"src", src, "dst", dst, "refresh", refresh)
	}
}

// AS serves the AS request.
func (s *DaemonServer) AS(ctx context.Context, req *daemon.ASRequest) (*daemon.ASResponse, error) {
	start := time.Now()
	response, err := s.as(ctx, req)
	s.Metrics.ASRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) as(ctx context.Context, req *daemon.ASRequest) (*daemon.ASResponse, error) {
	reqIA := addr.IA(req.IsdAs)
	if reqIA.IsZero() {
		reqIA = s.IA
	}
	mtu := uint32(0)
	if reqIA.Equal(s.IA) {
		mtu = uint32(s.MTU)
	}
	core, err := s.ASInspector.HasAttributes(ctx, reqIA, trust.Core)
	if err != nil {
		log.FromCtx(ctx).Error("Inspecting ISD-AS", "err", err, "isd_as", reqIA)
		return nil, serrors.Wrap("inspecting ISD-AS", err, "isd_as", reqIA)
	}
	reply := &daemon.ASResponse{
		IsdAs: uint64(reqIA),
		Core:  core,
		Mtu:   mtu,
	}
	return reply, nil
}

// Interfaces serves the interfaces request.
func (s *DaemonServer) Interfaces(ctx context.Context,
	req *daemon.InterfacesRequest,
) (*daemon.InterfacesResponse, error) {
	start := time.Now()
	response, err := s.interfaces(ctx, req)
	s.Metrics.InterfacesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) interfaces(ctx context.Context,
	_ *daemon.InterfacesRequest,
) (*daemon.InterfacesResponse, error) {
	reply := &daemon.InterfacesResponse{
		Interfaces: make(map[uint64]*daemon.Interface),
	}
	topo := s.Topology
	for _, ifID := range topo.IfIDs() {
		nextHop := topo.UnderlayNextHop(ifID)
		if nextHop == nil {
			continue
		}
		reply.Interfaces[uint64(ifID)] = &daemon.Interface{
			Address: &daemon.Underlay{
				Address: nextHop.String(),
			},
		}
	}
	return reply, nil
}

// Services serves the services request.
func (s *DaemonServer) Services(ctx context.Context,
	req *daemon.ServicesRequest,
) (*daemon.ServicesResponse, error) {
	start := time.Now()
	respsonse, err := s.services(ctx, req)
	s.Metrics.ServicesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return respsonse, unwrapMetricsError(err)
}

func (s *DaemonServer) services(ctx context.Context,
	_ *daemon.ServicesRequest,
) (*daemon.ServicesResponse, error) {
	reply := &daemon.ServicesResponse{
		Services: make(map[string]*daemon.ListService),
	}
	list := &daemon.ListService{}
	for _, h := range s.Topology.ControlServiceAddresses() {
		// TODO(lukedirtwalker): build actual URI after it's defined (anapapaya/scion#3587)
		list.Services = append(list.Services, &daemon.Service{Uri: h.String()})
	}
	reply.Services[topology.Control.String()] = list
	return reply, nil
}

// NotifyInterfaceDown notifies the server about an interface that is down.
func (s *DaemonServer) NotifyInterfaceDown(ctx context.Context,
	req *daemon.NotifyInterfaceDownRequest,
) (*daemon.NotifyInterfaceDownResponse, error) {
	start := time.Now()
	response, err := s.notifyInterfaceDown(ctx, req)
	s.Metrics.InterfaceDownNotifications.inc(
		ifDownLabels{Result: errToMetricResult(err), Src: "notification"},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) notifyInterfaceDown(ctx context.Context,
	req *daemon.NotifyInterfaceDownRequest,
) (*daemon.NotifyInterfaceDownResponse, error) {
	revInfo := &path_mgmt.RevInfo{
		RawIsdas:     addr.IA(req.IsdAs),
		IfID:         iface.ID(req.Id),
		LinkType:     proto.LinkType_core,
		RawTTL:       10,
		RawTimestamp: util.TimeToSecs(time.Now()),
	}
	_, err := s.RevCache.Insert(ctx, revInfo)
	if err != nil {
		log.FromCtx(ctx).Error("Inserting revocation", "err", err, "req", req)
		return nil, metricsError{
			err:    serrors.Wrap("inserting revocation", err),
			result: prom.ErrDB,
		}
	}
	return &daemon.NotifyInterfaceDownResponse{}, nil
}

// PortRange returns the port range for the dispatched ports.
func (s *DaemonServer) PortRange(
	_ context.Context,
	_ *emptypb.Empty,
) (*daemon.PortRangeResponse, error) {
	startPort, endPort := s.Topology.PortRange()
	return &daemon.PortRangeResponse{
		DispatchedPortStart: uint32(startPort),
		DispatchedPortEnd:   uint32(endPort),
	}, nil
}

func (s *DaemonServer) DRKeyASHost(
	ctx context.Context,
	req *daemon.DRKeyASHostRequest,
) (*daemon.DRKeyASHostResponse, error) {
	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	meta, err := requestToASHostMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf ASHostReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetASHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.Wrap("getting AS-Host from client store", err)
	}

	return &daemon.DRKeyASHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostAS(
	ctx context.Context,
	req *daemon.DRKeyHostASRequest,
) (*daemon.DRKeyHostASResponse, error) {
	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	meta, err := requestToHostASMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf HostASReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetHostASKey(ctx, meta)
	if err != nil {
		return nil, serrors.Wrap("getting Host-AS from client store", err)
	}

	return &daemon.DRKeyHostASResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostHost(
	ctx context.Context,
	req *daemon.DRKeyHostHostRequest,
) (*daemon.DRKeyHostHostResponse, error) {
	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	meta, err := requestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf HostHostReq", err)
	}
	lvl2Key, err := s.DRKeyClient.GetHostHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.Wrap("getting Host-Host from client store", err)
	}

	return &daemon.DRKeyHostHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func requestToASHostMeta(req *daemon.DRKeyASHostRequest) (drkey.ASHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.ASHostMeta{}, serrors.Wrap("invalid valTime from pb request", err)
	}
	return drkey.ASHostMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		DstHost:  req.DstHost,
	}, nil
}

func requestToHostASMeta(req *daemon.DRKeyHostASRequest) (drkey.HostASMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostASMeta{}, serrors.Wrap("invalid valTime from pb request", err)
	}
	return drkey.HostASMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		SrcHost:  req.SrcHost,
	}, nil
}

func requestToHostHostMeta(req *daemon.DRKeyHostHostRequest) (drkey.HostHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostHostMeta{}, serrors.Wrap("invalid valTime from pb request", err)
	}
	return drkey.HostHostMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		SrcHost:  req.SrcHost,
		DstHost:  req.DstHost,
	}, nil
}
