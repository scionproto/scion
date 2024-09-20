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
	"context"
	"net"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	dpb "github.com/scionproto/scion/pkg/proto/discovery"
	"github.com/scionproto/scion/pkg/snet"
)

// Discoverer discovers the gateways for a specific remote AS.
type Discoverer struct {
	Remote addr.IA
	Dialer grpc.Dialer
	Paths  control.PathMonitorRegistration
}

func (d Discoverer) Gateways(ctx context.Context) ([]control.Gateway, error) {
	paths := d.Paths.Get().Paths
	if len(paths) == 0 {
		return nil, serrors.New("no path available")
	}
	ds := &snet.SVCAddr{
		IA:      d.Remote,
		Path:    paths[0].Dataplane(),
		NextHop: paths[0].UnderlayNextHop(),
		SVC:     addr.SvcDS,
	}
	conn, err := d.Dialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.Gateways(ctx, &dpb.GatewaysRequest{}, grpc.RetryProfile...)
	if err != nil {
		return nil, serrors.Wrap("receiving gateways", err)
	}
	gateways := make([]control.Gateway, 0, len(rep.Gateways))
	for _, pb := range rep.Gateways {
		ctrl, err := net.ResolveUDPAddr("udp", pb.ControlAddress)
		if err != nil {
			return nil, serrors.Wrap("parsing control address", err)
		}
		data, err := net.ResolveUDPAddr("udp", pb.DataAddress)
		if err != nil {
			return nil, serrors.Wrap("parsing data address", err)
		}
		probe, err := net.ResolveUDPAddr("udp", pb.ProbeAddress)
		if err != nil {
			return nil, serrors.Wrap("parsing probe address", err)
		}
		gateways = append(gateways, control.Gateway{
			Control:    ctrl,
			Probe:      probe,
			Data:       data,
			Interfaces: pb.AllowInterfaces,
		})
	}
	return gateways, nil
}
