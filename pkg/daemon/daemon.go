// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package daemon provides APIs for querying SCION Daemons.
package daemon

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/internal/metrics"
	libmetrics "github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// Errors for SCION Daemon API requests
var (
	ErrUnableToConnect = serrors.New("unable to connect to the SCION Daemon")
)

const (
	// DefaultAPIAddress contains the system default for a daemon API socket.
	DefaultAPIAddress = "127.0.0.1:30255"
	// DefaultAPIPort contains the default port for a daemon client API socket.
	DefaultAPIPort = 30255
)

// NewService returns a SCION Daemon API connection factory.
// Deprecated: Use Service struct directly instead.
func NewService(name string) Service {
	return Service{
		Address: name,
		Metrics: Metrics{
			Connects: libmetrics.NewPromCounter(metrics.Conns.CounterVec()),
			PathsRequests: libmetrics.NewPromCounter(
				metrics.PathRequests.CounterVec()),
			ASRequests:                 libmetrics.NewPromCounter(metrics.ASInfos.CounterVec()),
			InterfacesRequests:         libmetrics.NewPromCounter(metrics.IFInfos.CounterVec()),
			ServicesRequests:           libmetrics.NewPromCounter(metrics.SVCInfos.CounterVec()),
			InterfaceDownNotifications: libmetrics.NewPromCounter(metrics.Revocations.CounterVec()),
		},
	}
}

// A Connector is used to query the SCION daemon. All connector methods block until
// either an error occurs, or the method successfully returns.
type Connector interface {
	// LocalIA requests from the daemon the local ISD-AS number.
	LocalIA(ctx context.Context) (addr.IA, error)
	// Paths requests from the daemon a set of end to end paths between the source and destination.
	Paths(ctx context.Context, dst, src addr.IA, f PathReqFlags) ([]snet.Path, error)
	// ASInfo requests from the daemon information about AS ia, the zero IA can be
	// use to detect the local IA.
	ASInfo(ctx context.Context, ia addr.IA) (ASInfo, error)
	// IFInfo requests from SCION Daemon addresses and ports of interfaces. Slice
	// ifs contains interface IDs of BRs. If empty, a fresh (i.e., uncached)
	// answer containing all interfaces is returned.
	IFInfo(ctx context.Context, ifs []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error)
	// SVCInfo requests from the daemon information about addresses and ports of
	// infrastructure services.  Slice svcTypes contains a list of desired
	// service types. If unset, a fresh (i.e., uncached) answer containing all
	// service types is returned. The reply is a map from service type to a list
	// of URIs of the service in the local AS.
	SVCInfo(ctx context.Context, svcTypes []addr.HostSVC) (map[addr.HostSVC][]string, error)
	// RevNotification sends a RevocationInfo message to the daemon.
	RevNotification(ctx context.Context, revInfo *path_mgmt.RevInfo) error
	// Close shuts down the connection to the daemon.
	Close() error
}
