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
	"fmt"
	"net"

	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/sciond/internal/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/proto"
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

// Service describes a SCIOND endpoint. New connections to SCIOND can be
// initialized via Connect.
type Service interface {
	// Connect connects to the SCIOND server described by Service. Future
	// method calls on the returned Connector request information from SCIOND.
	Connect(context.Context) (Connector, error)
}

type service struct {
	path string
}

// NewService returns a SCIOND API connection factory.
func NewService(name string) Service {
	return &service{path: name}
}

func (s *service) Connect(ctx context.Context) (Connector, error) {
	return newConn(ctx, s.path)
}

// A Connector is used to query SCIOND. All connector methods block until
// either an error occurs, or the method successfully returns.
type Connector interface {
	// LocalIA requests from SCIOND the local ISD-AS number.
	LocalIA(ctx context.Context) (addr.IA, error)
	// Paths requests from SCIOND a set of end to end paths between the source and destination.
	Paths(ctx context.Context, dst, src addr.IA, f PathReqFlags) ([]snet.Path, error)
	// ASInfo requests from SCIOND information about AS ia.
	ASInfo(ctx context.Context, ia addr.IA) (*ASInfoReply, error)
	// IFInfo requests from SCIOND addresses and ports of interfaces. Slice
	// ifs contains interface IDs of BRs. If empty, a fresh (i.e., uncached)
	// answer containing all interfaces is returned.
	IFInfo(ctx context.Context, ifs []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error)
	// SVCInfo requests from SCIOND information about addresses and ports of
	// infrastructure services.  Slice svcTypes contains a list of desired
	// service types. If unset, a fresh (i.e., uncached) answer containing all
	// service types is returned.
	SVCInfo(ctx context.Context, svcTypes []proto.ServiceType) (*ServiceInfoReply, error)
	// RevNotification sends a raw revocation to SCIOND, as contained in an
	// SCMP message.
	RevNotificationFromRaw(ctx context.Context, b []byte) (*RevReply, error)
	// RevNotification sends a RevocationInfo message to SCIOND.
	RevNotification(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo) (*RevReply, error)
	// Close shuts down the connection to a SCIOND server.
	Close(ctx context.Context) error
}

type conn struct {
	address string
}

func newConn(ctx context.Context, address string) (*conn, error) {
	c := &conn{address: address}
	// Test during initialization that SCIOND is alive; this helps catch some
	// unfixable issues (like bad socket name) while apps are still
	// initializing their networking.
	if err := c.checkForSciond(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *conn) checkForSciond(ctx context.Context) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return serrors.Wrap(ErrUnableToConnect, err)
	}
	defer conn.Close()
	// FIXME(roosd): This is hack until we have a proper health check.
	_, err = roundTrip(
		&Pld{
			TraceId:   tracing.IDFromCtx(ctx),
			Which:     proto.SCIONDMsg_Which_asInfoReq,
			AsInfoReq: &ASInfoReq{},
		},
		conn,
	)
	return err
}

// connect establishes a connection to SCIOND.
func (c *conn) connect(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", c.address)
	if err != nil {
		metrics.Conns.Inc(errorToPrometheusLabel(err))
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			metrics.Conns.Inc(errorToPrometheusLabel(err))
			return nil, err
		}
	}
	return conn, nil
}

func (c *conn) Paths(ctx context.Context, dst, src addr.IA,
	f PathReqFlags) ([]snet.Path, error) {

	conn, err := c.connect(ctx)
	if err != nil {
		metrics.PathRequests.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	defer conn.Close()

	reply, err := roundTrip(
		&Pld{
			TraceId: tracing.IDFromCtx(ctx),
			Which:   proto.SCIONDMsg_Which_pathReq,
			PathReq: &PathReq{
				Dst:   dst.IAInt(),
				Src:   src.IAInt(),
				Flags: f,
			},
		},
		conn,
	)
	if err != nil {
		metrics.PathRequests.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get Paths", err)
	}
	metrics.PathRequests.Inc(metrics.OkSuccess)
	return pathReplyToPaths(reply.PathReply, dst)
}

func (c *conn) LocalIA(ctx context.Context) (addr.IA, error) {
	asInfo, err := c.ASInfo(ctx, addr.IA{})
	if err != nil {
		return addr.IA{}, err
	}
	ia := asInfo.Entries[0].RawIsdas.IA()
	return ia, nil
}

func (c *conn) ASInfo(ctx context.Context, ia addr.IA) (*ASInfoReply, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		metrics.ASInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	pld, err := roundTrip(
		&Pld{
			TraceId: tracing.IDFromCtx(ctx),
			Which:   proto.SCIONDMsg_Which_asInfoReq,
			AsInfoReq: &ASInfoReq{
				Isdas: ia.IAInt(),
			},
		},
		conn,
	)
	if err != nil {
		metrics.ASInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get ASInfo", err)
	}
	metrics.ASInfos.Inc(metrics.OkSuccess)
	return pld.AsInfoReply, nil
}

func (c *conn) IFInfo(ctx context.Context,
	ifs []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error) {

	conn, err := c.connect(ctx)
	if err != nil {
		metrics.IFInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	pld, err := roundTrip(
		&Pld{
			TraceId: tracing.IDFromCtx(ctx),
			Which:   proto.SCIONDMsg_Which_ifInfoRequest,
			IfInfoRequest: &IFInfoRequest{
				IfIDs: ifs,
			},
		},
		conn,
	)
	if err != nil {
		metrics.IFInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get IFInfo", err)
	}
	metrics.IFInfos.Inc(metrics.OkSuccess)
	return ifinfoReplyToMap(pld.IfInfoReply), nil
}

func (c *conn) SVCInfo(ctx context.Context,
	svcTypes []proto.ServiceType) (*ServiceInfoReply, error) {

	conn, err := c.connect(ctx)
	if err != nil {
		metrics.SVCInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	pld, err := roundTrip(
		&Pld{
			TraceId: tracing.IDFromCtx(ctx),
			Which:   proto.SCIONDMsg_Which_serviceInfoRequest,
			ServiceInfoRequest: &ServiceInfoRequest{
				ServiceTypes: svcTypes,
			},
		},
		conn,
	)
	if err != nil {
		metrics.SVCInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get SVCInfo", err)
	}
	metrics.SVCInfos.Inc(metrics.OkSuccess)
	return pld.ServiceInfoReply, nil
}

func (c *conn) RevNotificationFromRaw(ctx context.Context, b []byte) (*RevReply, error) {
	// Extract information from notification
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(b)
	if err != nil {
		return nil, err
	}
	return c.RevNotification(ctx, sRevInfo)
}

func (c *conn) RevNotification(ctx context.Context,
	sRevInfo *path_mgmt.SignedRevInfo) (*RevReply, error) {

	conn, err := c.connect(ctx)
	if err != nil {
		metrics.Revocations.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	reply, err := roundTrip(
		&Pld{
			TraceId: tracing.IDFromCtx(ctx),
			Which:   proto.SCIONDMsg_Which_revNotification,
			RevNotification: &RevNotification{
				SRevInfo: sRevInfo,
			},
		},
		conn,
	)
	if err != nil {
		metrics.Revocations.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to send RevNotification", err)
	}
	metrics.Revocations.Inc(metrics.OkSuccess)
	return reply.RevReply, nil
}

func (c *conn) Close(_ context.Context) error {
	return nil
}

// GetDefaultSCIONDAddress return default sciond path for a given IA
func GetDefaultSCIONDAddress(ia *addr.IA) string {
	if ia == nil || ia.IsZero() {
		return DefaultSCIONDAddress
	}
	return fmt.Sprintf("127.0.0.%d:30255", ia.A%256)
}

func errorToPrometheusLabel(err error) string {
	switch {
	case err == nil:
		return metrics.OkSuccess
	case serrors.IsTimeout(err):
		return metrics.ErrTimeout
	default:
		return metrics.ErrNotClassified
	}
}

func Send(pld *Pld, conn net.Conn) error {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return serrors.WrapStr("unable to create capnp message", err)
	}
	root, err := proto.NewRootSCIONDMsg(seg)
	if err != nil {
		return serrors.WrapStr("unable to create capnp root", err)
	}
	if err := pogs.Insert(proto.SCIONDMsg_TypeID, root.Struct, pld); err != nil {
		return serrors.WrapStr("unable to insert struct data into capnp object", err)
	}
	if err := capnp.NewEncoder(conn).Encode(msg); err != nil {
		return serrors.WrapStr("unable to encode capnp message", err)
	}
	return nil
}

func receive(conn net.Conn) (*Pld, error) {
	msg, err := proto.SafeDecode(capnp.NewDecoder(conn))
	if err != nil {
		return nil, serrors.WrapStr("unable to decode RPC request", err)
	}

	root, err := msg.RootPtr()
	if err != nil {
		return nil, serrors.WrapStr("unable to extract capnp root", err)
	}

	p := &Pld{}
	if err := proto.SafeExtract(p, proto.SCIONDMsg_TypeID, root.Struct()); err != nil {
		return nil, serrors.New("unable to extract capnp SCIOND payload", "err", err)
	}
	return p, nil
}

func roundTrip(pld *Pld, conn net.Conn) (*Pld, error) {
	if err := Send(pld, conn); err != nil {
		return nil, serrors.WrapStr("send request failed", err)
	}
	pld, err := receive(conn)
	if err != nil {
		return nil, serrors.WrapStr("receive reply failed", err)
	}
	return pld, nil
}
