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

// Package sciond queries local SCIOND servers for information.
//
// To query SCIOND, initialize a Service object by passing in the path to the
// UNIX socket. It is then possible to establish connections to SCIOND by
// calling Connect or ConnectTimeout on the service. The connections implement
// interface Connector, whose methods can be used to talk to SCIOND.
//
// Connector method calls return the entire answer of SCIOND.
//
// Fields prefixed with Raw (e.g., RawErrorCode) contain data in the format
// received from SCIOND.  These are used internally, and the accessors without
// the prefix (e.g., ErrorCode()) should be used instead.
package sciond

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/sciond/internal/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

// Errors for SCIOND API requests
var (
	ErrUnableToConnect = serrors.New("unable to connect to SCIOND")
)

const (
	// DefaultSCIONDAddress contains the system default for a SCIOND socket.
	DefaultSCIONDAddress = "127.0.0.1:30255"
	// DefaultSCIONDPort contains the default port for a SCIOND client API socket.
	DefaultSCIONDPort = 30255
)

// NewService returns a SCIOND API connection factory.
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

// A Connector is used to query SCIOND. All connector methods block until
// either an error occurs, or the method successfully returns.
type Connector interface {
	// LocalIA requests from SCIOND the local ISD-AS number.
	LocalIA(ctx context.Context) (addr.IA, error)
	// Paths requests from SCIOND a set of end to end paths between the source and destination.
	Paths(ctx context.Context, dst, src addr.IA, f PathReqFlags) ([]snet.Path, error)
	// ASInfo requests from SCIOND information about AS ia, the zero IA can be
	// use to detect the local IA.
	ASInfo(ctx context.Context, ia addr.IA) (ASInfo, error)
	// IFInfo requests from SCIOND addresses and ports of interfaces. Slice
	// ifs contains interface IDs of BRs. If empty, a fresh (i.e., uncached)
	// answer containing all interfaces is returned.
	IFInfo(ctx context.Context, ifs []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error)
	// SVCInfo requests from SCIOND information about addresses and ports of
	// infrastructure services.  Slice svcTypes contains a list of desired
	// service types. If unset, a fresh (i.e., uncached) answer containing all
	// service types is returned. The reply is a map from service type to URI of
	// the service.
	SVCInfo(ctx context.Context, svcTypes []addr.HostSVC) (map[addr.HostSVC]string, error)
	// RevNotification sends a raw revocation to SCIOND, as contained in an
	// SCMP message.
	RevNotificationFromRaw(ctx context.Context, b []byte) error
	// RevNotification sends a RevocationInfo message to SCIOND.
	RevNotification(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo) error
	// Close shuts down the connection to a SCIOND server.
	Close(ctx context.Context) error
}
