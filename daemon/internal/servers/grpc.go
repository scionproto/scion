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
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/private/trust"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	daemonpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slices"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology"
)

// DaemonServer handles gRPC requests and delegates to a Connector implementation.
type DaemonServer struct {
	Connector   daemon.Connector
	ASInspector trust.Inspector
}

// NewDaemonServer creates a new DaemonServer with the given connector.
func NewDaemonServer(connector daemon.Connector) *DaemonServer {
	return &DaemonServer{
		Connector: connector,
	}
}

// Paths serves the paths gRPC request.
func (s *DaemonServer) Paths(ctx context.Context,
	req *daemonpb.PathsRequest,
) (*daemonpb.PathsResponse, error) {
	srcIA := addr.IA(req.SourceIsdAs)
	dstIA := addr.IA(req.DestinationIsdAs)

	flags := daemon.PathReqFlags{
		Refresh: req.Refresh,
	}

	paths, err := s.Connector.Paths(ctx, dstIA, srcIA, flags)
	if err != nil {
		return nil, err
	}

	reply := &daemonpb.PathsResponse{}
	for _, p := range paths {
		reply.Paths = append(reply.Paths, pathToPB(p))
	}
	return reply, nil
}

func pathToPB(path snet.Path) *daemonpb.Path {
	meta := path.Metadata()
	interfaces := make([]*daemonpb.PathInterface, len(meta.Interfaces))
	for i, intf := range meta.Interfaces {
		interfaces[i] = &daemonpb.PathInterface{
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

	geo := make([]*daemonpb.GeoCoordinates, len(meta.Geo))
	for i, v := range meta.Geo {
		geo[i] = &daemonpb.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}

	linkType := make([]daemonpb.LinkType, len(meta.LinkType))
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

	epicAuths := &daemonpb.EpicAuths{
		AuthPhvf: append([]byte(nil), meta.EpicAuths.AuthPHVF...),
		AuthLhvf: append([]byte(nil), meta.EpicAuths.AuthLHVF...),
	}

	var discovery map[uint64]*daemonpb.DiscoveryInformation
	if di := meta.DiscoveryInformation; di != nil {
		discovery = make(map[uint64]*daemonpb.DiscoveryInformation, len(di))
		for ia, info := range di {
			discovery[uint64(ia)] = &daemonpb.DiscoveryInformation{
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

	return &daemonpb.Path{
		Raw: raw,
		Interface: &daemonpb.Interface{
			Address: &daemonpb.Underlay{Address: nextHopStr},
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

func linkTypeToPB(lt snet.LinkType) daemonpb.LinkType {
	switch lt {
	case snet.LinkTypeDirect:
		return daemonpb.LinkType_LINK_TYPE_DIRECT
	case snet.LinkTypeMultihop:
		return daemonpb.LinkType_LINK_TYPE_MULTI_HOP
	case snet.LinkTypeOpennet:
		return daemonpb.LinkType_LINK_TYPE_OPEN_NET
	default:
		return daemonpb.LinkType_LINK_TYPE_UNSPECIFIED
	}
}

// AS serves the AS gRPC request.
func (s *DaemonServer) AS(ctx context.Context, req *daemonpb.ASRequest) (*daemonpb.ASResponse, error) {
	reqIA := addr.IA(req.IsdAs)

	info, err := s.Connector.ASInfo(ctx, reqIA)
	if err != nil {
		return nil, err
	}
	reqIA = info.IA

	core, err := s.ASInspector.HasAttributes(ctx, reqIA, trust.Core)
	if err != nil {
		log.FromCtx(ctx).Error("Inspecting ISD-AS", "err", err, "isd_as", reqIA)
		return nil, serrors.Wrap("inspecting ISD-AS", err, "isd_as", reqIA)
	}

	return &daemonpb.ASResponse{
		IsdAs: uint64(info.IA),
		Core:  core,
		Mtu:   uint32(info.MTU),
	}, nil
}

// Interfaces serves the interfaces gRPC request.
func (s *DaemonServer) Interfaces(ctx context.Context,
	req *daemonpb.InterfacesRequest,
) (*daemonpb.InterfacesResponse, error) {
	interfaces, err := s.Connector.Interfaces(ctx)
	if err != nil {
		return nil, err
	}

	reply := &daemonpb.InterfacesResponse{
		Interfaces: make(map[uint64]*daemonpb.Interface),
	}

	for ifID, addrPort := range interfaces {
		reply.Interfaces[uint64(ifID)] = &daemonpb.Interface{
			Address: &daemonpb.Underlay{
				Address: addrPort.String(),
			},
		}
	}

	return reply, nil
}

// Services serves the services gRPC request.
func (s *DaemonServer) Services(ctx context.Context,
	req *daemonpb.ServicesRequest,
) (*daemonpb.ServicesResponse, error) {

	var svcTypes []addr.SVC

	svcInfo, err := s.Connector.SVCInfo(ctx, svcTypes)
	if err != nil {
		return nil, err
	}

	reply := &daemonpb.ServicesResponse{
		Services: make(map[string]*daemonpb.ListService),
	}

	for svcType, uris := range svcInfo {
		list := &daemonpb.ListService{}
		for _, uri := range uris {
			list.Services = append(list.Services, &daemonpb.Service{Uri: uri})
		}
		// Map SVC type to string reprxesentation
		if svcType == addr.SVC(topology.Control) {
			reply.Services[topology.Control.String()] = list
		}
	}

	return reply, nil
}

// NotifyInterfaceDown notifies about an interface that is down.
func (s *DaemonServer) NotifyInterfaceDown(ctx context.Context,
	req *daemonpb.NotifyInterfaceDownRequest,
) (*daemonpb.NotifyInterfaceDownResponse, error) {
	revInfo := &path_mgmt.RevInfo{
		RawIsdas:     addr.IA(req.IsdAs),
		IfID:         iface.ID(req.Id),
		LinkType:     proto.LinkType_core,
		RawTTL:       10,
		RawTimestamp: util.TimeToSecs(time.Now()),
	}

	err := s.Connector.RevNotification(ctx, revInfo)
	if err != nil {
		return nil, err
	}

	return &daemonpb.NotifyInterfaceDownResponse{}, nil
}

// PortRange returns the port range for dispatched ports.
func (s *DaemonServer) PortRange(
	ctx context.Context,
	_ *emptypb.Empty,
) (*daemonpb.PortRangeResponse, error) {
	startPort, endPort, err := s.Connector.PortRange(ctx)
	if err != nil {
		return nil, err
	}

	return &daemonpb.PortRangeResponse{
		DispatchedPortStart: uint32(startPort),
		DispatchedPortEnd:   uint32(endPort),
	}, nil
}

// DRKeyASHost handles AS-Host DRKey gRPC requests.
func (s *DaemonServer) DRKeyASHost(
	ctx context.Context,
	req *daemonpb.DRKeyASHostRequest,
) (*daemonpb.DRKeyASHostResponse, error) {
	meta, err := requestToASHostMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf ASHostReq", err)
	}

	key, err := s.Connector.DRKeyGetASHostKey(ctx, meta)
	if err != nil {
		return nil, err
	}

	return &daemonpb.DRKeyASHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: key.Epoch.NotAfter.Unix()},
		Key:        key.Key[:],
	}, nil
}

// DRKeyHostAS handles Host-AS DRKey gRPC requests.
func (s *DaemonServer) DRKeyHostAS(
	ctx context.Context,
	req *daemonpb.DRKeyHostASRequest,
) (*daemonpb.DRKeyHostASResponse, error) {
	meta, err := requestToHostASMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf HostASReq", err)
	}

	key, err := s.Connector.DRKeyGetHostASKey(ctx, meta)
	if err != nil {
		return nil, err
	}

	return &daemonpb.DRKeyHostASResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: key.Epoch.NotAfter.Unix()},
		Key:        key.Key[:],
	}, nil
}

// DRKeyHostHost handles Host-Host DRKey gRPC requests.
func (s *DaemonServer) DRKeyHostHost(
	ctx context.Context,
	req *daemonpb.DRKeyHostHostRequest,
) (*daemonpb.DRKeyHostHostResponse, error) {
	meta, err := requestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.Wrap("parsing protobuf HostHostReq", err)
	}

	key, err := s.Connector.DRKeyGetHostHostKey(ctx, meta)
	if err != nil {
		return nil, err
	}

	return &daemonpb.DRKeyHostHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: key.Epoch.NotAfter.Unix()},
		Key:        key.Key[:],
	}, nil
}

func requestToASHostMeta(req *daemonpb.DRKeyASHostRequest) (drkey.ASHostMeta, error) {
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

func requestToHostASMeta(req *daemonpb.DRKeyHostASRequest) (drkey.HostASMeta, error) {
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

func requestToHostHostMeta(req *daemonpb.DRKeyHostHostRequest) (drkey.HostHostMeta, error) {
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
