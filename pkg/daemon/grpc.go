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

package daemon

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	dkpb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology"
)

// Service exposes the API to connect to a SCION daemon service.
type Service struct {
	// Address is the address of the SCION daemon to connect to.
	Address string
	// Metrics are the metric counters that should be incremented when using the
	// connector.
	Metrics Metrics
}

func (s Service) Connect(ctx context.Context) (Connector, error) {
	a, err := net.ResolveTCPAddr("tcp", s.Address)
	if err != nil {
		s.Metrics.incConnects(err)
		return nil, serrors.WrapStr("resolving addr", err)
	}
	conn, err := libgrpc.SimpleDialer{}.Dial(ctx, a)
	if err != nil {
		s.Metrics.incConnects(err)
		return nil, serrors.WrapStr("dialing", err)
	}
	s.Metrics.incConnects(nil)
	return grpcConn{conn: conn, metrics: s.Metrics}, nil
}

type grpcConn struct {
	conn    *grpc.ClientConn
	metrics Metrics
}

func (c grpcConn) LocalIA(ctx context.Context) (addr.IA, error) {
	asInfo, err := c.ASInfo(ctx, 0)
	if err != nil {
		return 0, err
	}
	ia := asInfo.IA
	return ia, nil
}

func (c grpcConn) Paths(ctx context.Context, dst, src addr.IA,
	f PathReqFlags) ([]snet.Path, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	response, err := client.Paths(ctx, &sdpb.PathsRequest{
		SourceIsdAs:      uint64(src),
		DestinationIsdAs: uint64(dst),
		Hidden:           f.Hidden,
		Refresh:          f.Refresh,
	})
	if err != nil {
		c.metrics.incPaths(err)
		return nil, err
	}
	paths, err := pathResponseToPaths(response.Paths, dst)
	c.metrics.incPaths(err)
	return paths, err
}

func (c grpcConn) ASInfo(ctx context.Context, ia addr.IA) (ASInfo, error) {
	client := sdpb.NewDaemonServiceClient(c.conn)
	response, err := client.AS(ctx, &sdpb.ASRequest{IsdAs: uint64(ia)})
	if err != nil {
		c.metrics.incAS(err)
		return ASInfo{}, err
	}
	c.metrics.incAS(nil)
	return ASInfo{
		IA:  addr.IA(response.IsdAs),
		MTU: uint16(response.Mtu),
	}, nil
}

func (c grpcConn) IFInfo(ctx context.Context,
	_ []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	response, err := client.Interfaces(ctx, &sdpb.InterfacesRequest{})
	if err != nil {
		c.metrics.incInterface(err)
		return nil, err
	}
	result := make(map[common.IFIDType]*net.UDPAddr)
	for ifID, intf := range response.Interfaces {
		a, err := net.ResolveUDPAddr("udp", intf.Address.Address)
		if err != nil {
			c.metrics.incInterface(err)
			return nil, serrors.WrapStr("parsing reply", err, "raw_uri", intf.Address.Address)
		}
		result[common.IFIDType(ifID)] = a
	}
	c.metrics.incInterface(nil)
	return result, nil
}

func (c grpcConn) SVCInfo(
	ctx context.Context,
	_ []addr.HostSVC,
) (map[addr.HostSVC][]string, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	response, err := client.Services(ctx, &sdpb.ServicesRequest{})
	if err != nil {
		c.metrics.incServcies(err)
		return nil, err
	}
	result := make(map[addr.HostSVC][]string)
	for st, si := range response.Services {
		svc := topoServiceTypeToSVCAddr(topology.ServiceTypeFromString(st))
		if svc == addr.SvcNone || len(si.Services) == 0 {
			continue
		}
		var uris []string
		for _, s := range si.GetServices() {
			uris = append(uris, s.GetUri())
		}
		result[svc] = uris
	}
	c.metrics.incServcies(nil)
	return result, nil
}

func (c grpcConn) RevNotification(ctx context.Context, revInfo *path_mgmt.RevInfo) error {
	client := sdpb.NewDaemonServiceClient(c.conn)
	_, err := client.NotifyInterfaceDown(ctx, &sdpb.NotifyInterfaceDownRequest{
		Id:    uint64(revInfo.IfID),
		IsdAs: uint64(revInfo.RawIsdas),
	})
	c.metrics.incIfDown(err)
	return err

}

func (c grpcConn) DRKeyGetASHostKey(ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	pbReq := asHostMetaToProtoRequest(meta)
	reply, err := client.DRKeyASHost(ctx, pbReq)
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	key, err := getASHostKeyFromReply(reply, meta)
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	return key, nil
}

func (c grpcConn) DRKeyGetHostASKey(ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	req := hostASMetaToProtoRequest(meta)
	reply, err := client.DRKeyHostAS(ctx, req)
	if err != nil {
		return drkey.HostASKey{}, err
	}
	key, err := getHostASKeyFromReply(reply, meta)
	if err != nil {
		return drkey.HostASKey{}, err
	}
	return key, nil
}

func (c grpcConn) DRKeyGetHostHostKey(ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	pbReq := hostHostMetaToProtoRequest(meta)
	reply, err := client.DRKeyHostHost(ctx, pbReq)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	key, err := getHostHostKeyFromReply(reply, meta)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	return key, nil
}

func (c grpcConn) Close() error {
	return c.conn.Close()
}

func pathResponseToPaths(paths []*sdpb.Path, dst addr.IA) ([]snet.Path, error) {
	result := make([]snet.Path, 0, len(paths))
	for _, p := range paths {
		cp, err := convertPath(p, dst)
		if err != nil {
			return nil, err
		}
		result = append(result, cp)
	}
	return result, nil
}

func convertPath(p *sdpb.Path, dst addr.IA) (path.Path, error) {
	expiry := time.Unix(p.Expiration.Seconds, int64(p.Expiration.Nanos))
	if len(p.Interfaces) == 0 {
		return path.Path{
			Src: dst,
			Dst: dst,
			Meta: snet.PathMetadata{
				MTU:    uint16(p.Mtu),
				Expiry: expiry,
			},
			DataplanePath: path.Empty{},
		}, nil
	}
	underlayA, err := net.ResolveUDPAddr("udp", p.Interface.Address.Address)
	if err != nil {
		return path.Path{}, serrors.WrapStr("resolving underlay", err)
	}
	interfaces := make([]snet.PathInterface, len(p.Interfaces))
	for i, pi := range p.Interfaces {
		interfaces[i] = snet.PathInterface{
			ID: common.IFIDType(pi.Id),
			IA: addr.IA(pi.IsdAs),
		}
	}
	latency := make([]time.Duration, len(p.Latency))
	for i, v := range p.Latency {
		latency[i] = time.Second*time.Duration(v.Seconds) + time.Duration(v.Nanos)
	}
	geo := make([]snet.GeoCoordinates, len(p.Geo))
	for i, v := range p.Geo {
		geo[i] = snet.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]snet.LinkType, len(p.LinkType))
	for i, v := range p.LinkType {
		linkType[i] = linkTypeFromPB(v)
	}

	res := path.Path{
		Src: interfaces[0].IA,
		Dst: dst,
		DataplanePath: path.SCION{
			Raw: p.Raw,
		},
		NextHop: underlayA,
		Meta: snet.PathMetadata{
			Interfaces:   interfaces,
			MTU:          uint16(p.Mtu),
			Expiry:       expiry,
			Latency:      latency,
			Bandwidth:    p.Bandwidth,
			Geo:          geo,
			LinkType:     linkType,
			InternalHops: p.InternalHops,
			Notes:        p.Notes,
		},
	}

	if p.EpicAuths == nil {
		return res, nil
	}
	res.Meta.EpicAuths = snet.EpicAuths{
		AuthPHVF: append([]byte(nil), p.EpicAuths.AuthPhvf...),
		AuthLHVF: append([]byte(nil), p.EpicAuths.AuthLhvf...),
	}
	return res, nil
}

func linkTypeFromPB(lt sdpb.LinkType) snet.LinkType {
	switch lt {
	case sdpb.LinkType_LINK_TYPE_DIRECT:
		return snet.LinkTypeDirect
	case sdpb.LinkType_LINK_TYPE_MULTI_HOP:
		return snet.LinkTypeMultihop
	case sdpb.LinkType_LINK_TYPE_OPEN_NET:
		return snet.LinkTypeOpennet
	default:
		return snet.LinkTypeUnset
	}
}

func topoServiceTypeToSVCAddr(st topology.ServiceType) addr.HostSVC {
	switch st {
	case topology.Control:
		return addr.SvcCS
	default:
		return addr.SvcNone
	}
}

func asHostMetaToProtoRequest(meta drkey.ASHostMeta) *sdpb.DRKeyASHostRequest {
	return &sdpb.DRKeyASHostRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		DstHost:    meta.DstHost,
	}
}

func getASHostKeyFromReply(rep *sdpb.DRKeyASHostResponse,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}

	returningKey := drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		DstHost: meta.DstHost,
	}

	if len(rep.Key) != 16 {
		return drkey.ASHostKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func hostASMetaToProtoRequest(meta drkey.HostASMeta) *sdpb.DRKeyHostASRequest {
	return &sdpb.DRKeyHostASRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		SrcHost:    meta.SrcHost,
	}
}

func getHostASKeyFromReply(rep *sdpb.DRKeyHostASResponse,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}

	returningKey := drkey.HostASKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		SrcHost: meta.SrcHost,
	}
	if len(rep.Key) != 16 {
		return drkey.HostASKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func hostHostMetaToProtoRequest(meta drkey.HostHostMeta) *sdpb.DRKeyHostHostRequest {
	return &sdpb.DRKeyHostHostRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		DstHost:    meta.DstHost,
		SrcHost:    meta.SrcHost,
	}
}

func getHostHostKeyFromReply(rep *sdpb.DRKeyHostHostResponse,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}

	returningKey := drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
	}
	if len(rep.Key) != 16 {
		return drkey.HostHostKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}
