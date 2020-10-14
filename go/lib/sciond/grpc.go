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

package sciond

import (
	"context"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/spath"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	sdpb "github.com/scionproto/scion/go/pkg/proto/daemon"
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
	asInfo, err := c.ASInfo(ctx, addr.IA{})
	if err != nil {
		return addr.IA{}, err
	}
	ia := asInfo.IA
	return ia, nil
}

func (c grpcConn) Paths(ctx context.Context, dst, src addr.IA,
	f PathReqFlags) ([]snet.Path, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	response, err := client.Paths(ctx, &sdpb.PathsRequest{
		SourceIsdAs:      uint64(src.IAInt()),
		DestinationIsdAs: uint64(dst.IAInt()),
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
	response, err := client.AS(ctx, &sdpb.ASRequest{IsdAs: uint64(ia.IAInt())})
	if err != nil {
		c.metrics.incAS(err)
		return ASInfo{}, err
	}
	c.metrics.incAS(nil)
	return ASInfo{
		IA:  addr.IAInt(response.IsdAs).IA(),
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

func (c grpcConn) SVCInfo(ctx context.Context, _ []addr.HostSVC) (map[addr.HostSVC]string, error) {
	client := sdpb.NewDaemonServiceClient(c.conn)
	response, err := client.Services(ctx, &sdpb.ServicesRequest{})
	if err != nil {
		c.metrics.incServcies(err)
		return nil, err
	}
	result := make(map[addr.HostSVC]string)
	for st, si := range response.Services {
		svc := addr.HostSVCFromString(strings.ToUpper(st))
		if svc == addr.SvcNone || len(si.Services) == 0 {
			continue
		}
		result[svc] = si.Services[0].Uri
	}
	c.metrics.incServcies(nil)
	return result, nil
}

func (c grpcConn) RevNotificationFromRaw(ctx context.Context, b []byte) error {
	// Extract information from notification
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(b)
	if err != nil {
		return err
	}
	return c.RevNotification(ctx, sRevInfo)
}

func (c grpcConn) RevNotification(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo) error {
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		c.metrics.incIfDown(err)
		return serrors.WrapStr("extracting rev info", err)
	}

	client := sdpb.NewDaemonServiceClient(c.conn)
	_, err = client.NotifyInterfaceDown(ctx, &sdpb.NotifyInterfaceDownRequest{
		Id:    uint64(revInfo.IfID),
		IsdAs: uint64(revInfo.RawIsdas),
	})
	c.metrics.incIfDown(err)
	return err

}

func (c grpcConn) Close(_ context.Context) error {
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
			Dst: dst,
			Meta: path.PathMetadata{
				Mtu: uint16(p.Mtu),
				Exp: expiry,
			},
		}, nil
	}
	var sp *spath.Path
	if !p.HeaderV2 {
		sp = spath.New(p.Raw)
		if err := sp.InitOffsets(); err != nil {
			return path.Path{}, serrors.WrapStr("initializing path offsets", err)
		}
	} else {
		sp = spath.NewV2(p.Raw, false)
	}

	underlayA, err := net.ResolveUDPAddr("udp", p.Interface.Address.Address)
	if err != nil {
		return path.Path{}, serrors.WrapStr("resolving underlay", err)
	}
	interfaces := make([]snet.PathInterface, 0, len(p.Interfaces))
	for _, pi := range p.Interfaces {
		interfaces = append(interfaces, snet.PathInterface{
			ID: common.IFIDType(pi.Id),
			IA: addr.IAInt(pi.IsdAs).IA(),
		})
	}
	return path.Path{
		Dst:     dst,
		SPath:   sp,
		NextHop: underlayA,
		IFaces:  interfaces,
		Meta: path.PathMetadata{
			Mtu: uint16(p.Mtu),
			Exp: expiry,
		},
	}, nil
}
