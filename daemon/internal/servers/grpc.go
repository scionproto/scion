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

	durationpb "github.com/golang/protobuf/ptypes/duration"
	timestamppb "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/opentracing/opentracing-go"
	"golang.org/x/sync/singleflight"

	drkey_daemon "github.com/scionproto/scion/daemon/drkey"
	"github.com/scionproto/scion/daemon/fetcher"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	pb_daemon "github.com/scionproto/scion/pkg/proto/daemon"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

type Topology interface {
	InterfaceIDs() []uint16
	UnderlayNextHop(uint16) *net.UDPAddr
	ControlServiceAddresses() []*net.UDPAddr
}

// DaemonServer handles gRPC requests to the SCION daemon.
type DaemonServer struct {
	IA          addr.IA
	MTU         uint16
	Topology    Topology
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	ASInspector trust.Inspector
	DRKeyClient drkey_daemon.ClientEngine

	Metrics Metrics

	foregroundPathDedupe singleflight.Group
	backgroundPathDedupe singleflight.Group
}

// Paths serves the paths request.
func (s *DaemonServer) Paths(ctx context.Context,
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

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
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

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
	reply := &sdpb.PathsResponse{}
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
		func() (interface{}, error) {
			return s.Fetcher.GetPaths(ctx, src, dst, refresh)
		},
	)
	// just cast to the correct type, ignore the "ok", since that can only be
	// false in case of a nil result.
	paths, _ := r.([]snet.Path)
	return paths, err
}

func pathToPB(path snet.Path) *sdpb.Path {
	meta := path.Metadata()
	interfaces := make([]*sdpb.PathInterface, len(meta.Interfaces))
	for i, intf := range meta.Interfaces {
		interfaces[i] = &sdpb.PathInterface{
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
	geo := make([]*sdpb.GeoCoordinates, len(meta.Geo))
	for i, v := range meta.Geo {
		geo[i] = &sdpb.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]sdpb.LinkType, len(meta.LinkType))
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

	epicAuths := &sdpb.EpicAuths{
		AuthPhvf: append([]byte(nil), meta.EpicAuths.AuthPHVF...),
		AuthLhvf: append([]byte(nil), meta.EpicAuths.AuthLHVF...),
	}

	return &sdpb.Path{
		Raw: raw,
		Interface: &sdpb.Interface{
			Address: &sdpb.Underlay{Address: nextHopStr},
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

func linkTypeToPB(lt snet.LinkType) sdpb.LinkType {
	switch lt {
	case snet.LinkTypeDirect:
		return sdpb.LinkType_LINK_TYPE_DIRECT
	case snet.LinkTypeMultihop:
		return sdpb.LinkType_LINK_TYPE_MULTI_HOP
	case snet.LinkTypeOpennet:
		return sdpb.LinkType_LINK_TYPE_OPEN_NET
	default:
		return sdpb.LinkType_LINK_TYPE_UNSPECIFIED
	}
}

func (s *DaemonServer) backgroundPaths(origCtx context.Context, src, dst addr.IA, refresh bool) {
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
	span, ctx := opentracing.StartSpanFromContext(ctx, "fetch.paths.background", spanOpts...)
	defer span.Finish()
	if _, err := s.fetchPaths(ctx, &s.backgroundPathDedupe, src, dst, refresh); err != nil {
		log.FromCtx(ctx).Debug("Error fetching paths (background)", "err", err,
			"src", src, "dst", dst, "refresh", refresh)
	}
}

// AS serves the AS request.
func (s *DaemonServer) AS(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	start := time.Now()
	response, err := s.as(ctx, req)
	s.Metrics.ASRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) as(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
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
		return nil, serrors.WrapStr("inspecting ISD-AS", err, "isd_as", reqIA)
	}
	reply := &sdpb.ASResponse{
		IsdAs: uint64(reqIA),
		Core:  core,
		Mtu:   mtu,
	}
	return reply, nil
}

// Interfaces serves the interfaces request.
func (s *DaemonServer) Interfaces(ctx context.Context,
	req *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	start := time.Now()
	response, err := s.interfaces(ctx, req)
	s.Metrics.InterfacesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) interfaces(ctx context.Context,
	_ *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	reply := &sdpb.InterfacesResponse{
		Interfaces: make(map[uint64]*sdpb.Interface),
	}
	topo := s.Topology
	for _, ifID := range topo.InterfaceIDs() {
		nextHop := topo.UnderlayNextHop(ifID)
		if nextHop == nil {
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
func (s *DaemonServer) Services(ctx context.Context,
	req *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	start := time.Now()
	respsonse, err := s.services(ctx, req)
	s.Metrics.ServicesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return respsonse, unwrapMetricsError(err)
}

func (s *DaemonServer) services(ctx context.Context,
	_ *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	reply := &sdpb.ServicesResponse{
		Services: make(map[string]*sdpb.ListService),
	}
	list := &sdpb.ListService{}
	for _, h := range s.Topology.ControlServiceAddresses() {
		// TODO(lukedirtwalker): build actual URI after it's defined (anapapaya/scion#3587)
		list.Services = append(list.Services, &sdpb.Service{Uri: h.String()})
	}
	reply.Services[topology.Control.String()] = list
	return reply, nil
}

// NotifyInterfaceDown notifies the server about an interface that is down.
func (s *DaemonServer) NotifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	start := time.Now()
	response, err := s.notifyInterfaceDown(ctx, req)
	s.Metrics.InterfaceDownNotifications.inc(
		ifDownLabels{Result: errToMetricResult(err), Src: "notification"},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) notifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	revInfo := &path_mgmt.RevInfo{
		RawIsdas:     addr.IA(req.IsdAs),
		IfID:         common.IFIDType(req.Id),
		LinkType:     proto.LinkType_core,
		RawTTL:       10,
		RawTimestamp: util.TimeToSecs(time.Now()),
	}
	_, err := s.RevCache.Insert(ctx, revInfo)
	if err != nil {
		log.FromCtx(ctx).Error("Inserting revocation", "err", err, "req", req)
		return nil, metricsError{
			err:    serrors.WrapStr("inserting revocation", err),
			result: prom.ErrDB,
		}
	}
	return &sdpb.NotifyInterfaceDownResponse{}, nil
}

func (s *DaemonServer) DRKeyASHost(
	ctx context.Context,
	req *pb_daemon.DRKeyASHostRequest,
) (*pb_daemon.DRKeyASHostResponse, error) {

	meta, err := requestToASHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf ASHostReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetASHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting AS-Host from client store", err)
	}

	return &sdpb.DRKeyASHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostAS(
	ctx context.Context,
	req *pb_daemon.DRKeyHostASRequest,
) (*pb_daemon.DRKeyHostASResponse, error) {

	meta, err := requestToHostASMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf HostASReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetHostASKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting Host-AS from client store", err)
	}

	return &sdpb.DRKeyHostASResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostHost(
	ctx context.Context,
	req *pb_daemon.DRKeyHostHostRequest,
) (*pb_daemon.DRKeyHostHostResponse, error) {

	meta, err := requestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf HostHostReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetHostHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting Host-Host from client store", err)
	}

	return &sdpb.DRKeyHostHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func requestToASHostMeta(req *sdpb.DRKeyASHostRequest) (drkey.ASHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.ASHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.ASHostMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		DstHost:  req.DstHost,
	}, nil
}

func requestToHostASMeta(req *sdpb.DRKeyHostASRequest) (drkey.HostASMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostASMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.HostASMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		SrcHost:  req.SrcHost,
	}, nil
}

func requestToHostHostMeta(req *sdpb.DRKeyHostHostRequest) (drkey.HostHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
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
