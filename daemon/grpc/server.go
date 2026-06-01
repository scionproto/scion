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

package grpc

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/asinfo"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/private/engine"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/slices"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	drkeyengine "github.com/scionproto/scion/private/drkey"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

// Topology is the interface for accessing topology information.
type Topology interface {
	IfIDs() []uint16
	UnderlayNextHop(uint16) *net.UDPAddr
	ControlServiceAddresses() []*net.UDPAddr
	PortRange() (uint16, uint16)
}

// DaemonServer handles gRPC requests to the SCION daemon.
// It delegates business logic to the embedded DaemonEngine.
type DaemonServer struct {
	Engine  *engine.DaemonEngine
	Metrics Metrics
}

// NewDaemonServer creates a new DaemonServer with the given configuration.
func NewDaemonServer(
	ia addr.IA,
	mtu uint16,
	localASInfo asinfo.LocalASInfo,
	fetcher fetcher.Fetcher,
	revCache revcache.RevCache,
	asInspector trust.Inspector,
	drkeyClient *drkeyengine.ClientEngine,
	metrics Metrics,
) *DaemonServer {
	return &DaemonServer{
		Engine: &engine.DaemonEngine{
			IA:          ia,
			MTU:         mtu,
			LocalASInfo: localASInfo,
			Fetcher:     fetcher,
			RevCache:    revCache,
			ASInspector: asInspector,
			DRKeyClient: drkeyClient,
		},
		Metrics: metrics,
	}
}

// Paths serves the paths request.
func (s *DaemonServer) Paths(
	ctx context.Context,
	req *sdpb.PathsRequest,
) (*sdpb.PathsResponse, error) {
	start := time.Now()
	dstI := addr.IA(req.DestinationIsdAs).ISD()
	response, err := s.paths(ctx, req)
	s.Metrics.PathsRequests.inc(
		errToMetricResult(err), dstI,
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) paths(
	ctx context.Context,
	req *sdpb.PathsRequest,
) (*sdpb.PathsResponse, error) {
	srcIA, dstIA := addr.IA(req.SourceIsdAs), addr.IA(req.DestinationIsdAs)
	flags := daemontypes.PathReqFlags{
		Refresh: req.Refresh,
		Hidden:  req.Hidden,
	}
	paths, err := s.Engine.Paths(ctx, dstIA, srcIA, flags)
	if err != nil {
		return nil, err
	}
	reply := &sdpb.PathsResponse{}
	for _, p := range paths {
		reply.Paths = append(reply.Paths, pathToPB(p))
	}
	return reply, nil
}

// AS serves the AS request.
func (s *DaemonServer) AS(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	start := time.Now()
	response, err := s.as(ctx, req)
	s.Metrics.ASRequests.inc(
		errToMetricResult(err),
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) as(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	asInfo, err := s.Engine.ASInfo(ctx, addr.IA(req.IsdAs))
	if err != nil {
		return nil, err
	}
	// Note: We don't have the 'core' attribute in daemon.ASInfo,
	// so we need to query it directly here.
	reqIA := addr.IA(req.IsdAs)
	if reqIA.IsZero() {
		reqIA = s.Engine.IA
	}
	core, err := s.Engine.ASInspector.HasAttributes(ctx, reqIA, trust.Core)
	if err != nil {
		return nil, serrors.Wrap("inspecting ISD-AS", err, "isd_as", reqIA)
	}
	return &sdpb.ASResponse{
		IsdAs: uint64(asInfo.IA),
		Core:  core,
		Mtu:   uint32(asInfo.MTU),
	}, nil
}

// Interfaces serves the interfaces request.
func (s *DaemonServer) Interfaces(
	ctx context.Context,
	req *sdpb.InterfacesRequest,
) (*sdpb.InterfacesResponse, error) {
	start := time.Now()
	response, err := s.interfaces(ctx, req)
	s.Metrics.InterfacesRequests.inc(
		errToMetricResult(err),
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) interfaces(
	ctx context.Context,
	_ *sdpb.InterfacesRequest,
) (*sdpb.InterfacesResponse, error) {
	intfs, err := s.Engine.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	reply := &sdpb.InterfacesResponse{
		Interfaces: make(map[uint64]*sdpb.Interface),
	}
	for ifID, addr := range intfs {
		reply.Interfaces[uint64(ifID)] = &sdpb.Interface{
			Address: &sdpb.Underlay{
				Address: addr.String(),
			},
		}
	}
	return reply, nil
}

// Services serves the services request.
func (s *DaemonServer) Services(
	ctx context.Context,
	req *sdpb.ServicesRequest,
) (*sdpb.ServicesResponse, error) {
	start := time.Now()
	response, err := s.services(ctx, req)
	s.Metrics.ServicesRequests.inc(
		errToMetricResult(err),
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) services(
	ctx context.Context,
	_ *sdpb.ServicesRequest,
) (*sdpb.ServicesResponse, error) {
	uris, err := s.Engine.SVCInfo(ctx)
	if err != nil {
		return nil, err
	}
	reply := &sdpb.ServicesResponse{
		Services: make(map[string]*sdpb.ListService),
	}
	list := &sdpb.ListService{}
	for _, uri := range uris {
		list.Services = append(list.Services, &sdpb.Service{Uri: uri})
	}
	reply.Services[topology.Control.String()] = list
	return reply, nil
}

// NotifyInterfaceDown notifies the server about an interface that is down.
func (s *DaemonServer) NotifyInterfaceDown(
	ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest,
) (*sdpb.NotifyInterfaceDownResponse, error) {
	start := time.Now()
	response, err := s.notifyInterfaceDown(ctx, req)
	s.Metrics.InterfaceDownNotifications.inc(
		errToMetricResult(err), "notification",
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) notifyInterfaceDown(
	ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest,
) (*sdpb.NotifyInterfaceDownResponse, error) {
	err := s.Engine.NotifyInterfaceDown(ctx, addr.IA(req.IsdAs), req.Id)
	if err != nil {
		return nil, err
	}
	return &sdpb.NotifyInterfaceDownResponse{}, nil
}

// PortRange returns the port range for the dispatched ports.
func (s *DaemonServer) PortRange(
	ctx context.Context,
	_ *emptypb.Empty,
) (*sdpb.PortRangeResponse, error) {
	startPort, endPort, err := s.Engine.PortRange(ctx)
	if err != nil {
		return nil, err
	}
	return &sdpb.PortRangeResponse{
		DispatchedPortStart: uint32(startPort),
		DispatchedPortEnd:   uint32(endPort),
	}, nil
}

func (s *DaemonServer) DRKeyASHost(
	ctx context.Context,
	req *sdpb.DRKeyASHostRequest,
) (*sdpb.DRKeyASHostResponse, error) {
	meta, err := requestToASHostMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf ASHostReq", err)
	}
	lvl2Key, err := s.Engine.DRKeyGetASHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.Wrap("getting AS-Host from client store", err)
	}
	return &sdpb.DRKeyASHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostAS(
	ctx context.Context,
	req *sdpb.DRKeyHostASRequest,
) (*sdpb.DRKeyHostASResponse, error) {
	meta, err := requestToHostASMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf HostASReq", err)
	}
	lvl2Key, err := s.Engine.DRKeyGetHostASKey(ctx, meta)
	if err != nil {
		return nil, serrors.Wrap("getting Host-AS from client store", err)
	}
	return &sdpb.DRKeyHostASResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostHost(
	ctx context.Context,
	req *sdpb.DRKeyHostHostRequest,
) (*sdpb.DRKeyHostHostResponse, error) {
	meta, err := requestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf HostHostReq", err)
	}
	lvl2Key, err := s.Engine.DRKeyGetHostHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.Wrap("getting Host-Host from client store", err)
	}
	return &sdpb.DRKeyHostHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

// Protobuf conversion helpers

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
		AuthPhvf: bytes.Clone(meta.EpicAuths.AuthPHVF),
		AuthLhvf: bytes.Clone(meta.EpicAuths.AuthLHVF),
	}

	var discovery map[uint64]*sdpb.DiscoveryInformation
	if di := meta.DiscoveryInformation; di != nil {
		discovery = make(map[uint64]*sdpb.DiscoveryInformation, len(di))
		for ia, info := range di {
			discovery[uint64(ia)] = &sdpb.DiscoveryInformation{
				ControlServiceAddresses: slices.Transform(
					info.ControlServices,
					netip.AddrPort.String,
				),
				DiscoveryServiceAddresses: slices.Transform(
					info.DiscoveryServices,
					netip.AddrPort.String,
				),
			}
		}
	}

	return &sdpb.Path{
		Raw: raw,
		Interface: &sdpb.Interface{
			Address: &sdpb.Underlay{Address: nextHopStr},
		},
		Interfaces:           interfaces,
		Mtu:                  uint32(meta.MTU),
		Expiration:           &timestamppb.Timestamp{Seconds: meta.Expiry.Unix()},
		Latency:              latency,
		Bandwidth:            meta.Bandwidth,
		Geo:                  geo,
		LinkType:             linkType,
		InternalHops:         meta.InternalHops,
		Notes:                meta.Notes,
		EpicAuths:            epicAuths,
		DiscoveryInformation: discovery,
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

func requestToASHostMeta(req *sdpb.DRKeyASHostRequest) (drkey.ASHostMeta, error) {
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

func requestToHostASMeta(req *sdpb.DRKeyHostASRequest) (drkey.HostASMeta, error) {
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

func requestToHostHostMeta(req *sdpb.DRKeyHostHostRequest) (drkey.HostHostMeta, error) {
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
