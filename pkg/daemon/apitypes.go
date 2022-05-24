// Copyright 2019 Anapaya Systems
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
	"math/rand"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/topology"
)

type PathReqFlags struct {
	Refresh bool
	Hidden  bool
}

// ASInfo provides information about the local AS.
type ASInfo struct {
	IA  addr.IA
	MTU uint16
}

type Querier struct {
	Connector Connector
	IA        addr.IA
}

func (q Querier) Query(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	paths, err := q.Connector.Paths(ctx, dst, q.IA, PathReqFlags{})
	if err != nil {
		return paths, serrors.WrapStr("querying paths", err, "local_isd_as", q.IA)
	}
	return paths, nil
}

// RevHandler is an adapter for SCION Daemon connector to implement snet.RevocationHandler.
type RevHandler struct {
	Connector Connector
}

func (h RevHandler) Revoke(ctx context.Context, revInfo *path_mgmt.RevInfo) error {
	return h.Connector.RevNotification(ctx, revInfo)
}

// TopoQuerier can be used to get topology information from the SCION Daemon.
type TopoQuerier struct {
	Connector Connector
}

// UnderlayAnycast provides any address for the given svc type.
func (h TopoQuerier) UnderlayAnycast(ctx context.Context, svc addr.HostSVC) (*net.UDPAddr, error) {
	if err := checkSVC(svc); err != nil {
		return nil, err
	}
	r, err := h.Connector.SVCInfo(ctx, []addr.HostSVC{svc})
	if err != nil {
		return nil, err
	}
	entry, ok := r[svc]
	if !ok || len(entry) == 0 {
		return nil, serrors.New("no entry found", "svc", svc, "services", r)
	}
	a, err := net.ResolveUDPAddr("udp", entry[rand.Intn(len(entry))])
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: a.IP, Port: topology.EndhostPort, Zone: a.Zone}, nil
}

func checkSVC(svc addr.HostSVC) error {
	switch svc {
	case addr.SvcCS:
		return nil
	default:
		return serrors.New("invalid svc type", "svc", svc)
	}
}
