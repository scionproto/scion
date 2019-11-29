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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond/internal/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/proto"
)

// Errors for SCIOND API requests
var (
	ErrUnableToConnect = serrors.New("unable to connect to SCIOND")
)

const (
	// DefaultSCIONDPath contains the system default for a SCIOND socket.
	DefaultSCIONDPath = "/run/shm/sciond/default.sock"
	// DefaultSocketFileMode allows read/write to the user and group only.
	DefaultSocketFileMode = 0770
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

// A Connector is used to query SCIOND. The connector maintains an internal
// cache for interface, service and AS information. All connector methods block until either
// an error occurs, or the method successfully returns.
type Connector interface {
	// Paths requests from SCIOND a set of end to end paths between src and
	// dst. max specifies the maximum number of paths returned.
	Paths(ctx context.Context, dst, src addr.IA, max uint16, f PathReqFlags) ([]snet.Path, error)
	// ASInfo requests from SCIOND information about AS ia.
	ASInfo(ctx context.Context, ia addr.IA) (*ASInfoReply, error)
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
	requestID uint64
	path      string
}

func newConn(ctx context.Context, path string) (*conn, error) {
	c := &conn{path: path}
	// Test during initialization that SCIOND is alive; this helps catch some
	// unfixable issues (like bad socket name) while apps are still
	// initializing their networking.
	if err := c.checkForSciond(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *conn) checkForSciond(ctx context.Context) error {
	dispatcher, err := c.ctxAwareConnect(ctx)
	if err != nil {
		return serrors.Wrap(ErrUnableToConnect, err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		return serrors.WrapStr("Error when closing test SCIOND conn", err)
	}
	return nil
}

// ctxAwareConnect establishes a connection to SCIOND. The returned infra message dispatcher is not
// used for its request-response matching capabilities (because a single RPC is happening on each
// underlying connection), but rather for its context-aware API.
func (c *conn) ctxAwareConnect(ctx context.Context) (*disp.Dispatcher, error) {
	type returnValue struct {
		dispatcher *disp.Dispatcher
		err        error
	}
	barrier := make(chan returnValue, 1)
	go func() {
		defer log.LogPanicAndExit()
		dispatcher, err := dial(ctx, c.path)
		barrier <- returnValue{dispatcher: dispatcher, err: err}
	}()

	select {
	case rValue := <-barrier:
		metrics.Conns.Inc(errorToPrometheusLabel(rValue.err))
		return rValue.dispatcher, rValue.err
	case <-ctx.Done():
		// In the situation where ConnectTimeout doesn't finish and ctx is Done
		// via a cancellation function, this may (1) permanently leak a
		// goroutine, if ctx doesn't have a deadline, or (2) for a long amount
		// of time, if the deadline is very far into the future.
		metrics.Conns.Inc(errorToPrometheusLabel(ctx.Err()))
		return nil, ctx.Err()
	}
}

func (c *conn) Paths(ctx context.Context, dst, src addr.IA, max uint16,
	f PathReqFlags) ([]snet.Path, error) {

	roundTripper, err := c.ctxAwareConnect(ctx)
	if err != nil {
		metrics.PathRequests.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	defer roundTripper.Close(ctx)
	reply, err := roundTripper.Request(
		ctx,
		&Pld{
			Which: proto.SCIONDMsg_Which_pathReq,
			PathReq: &PathReq{
				Dst:      dst.IAInt(),
				Src:      src.IAInt(),
				MaxPaths: max,
				Flags:    f,
			},
		},
		nil,
	)
	if err != nil {
		metrics.PathRequests.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get Paths", err)
	}
	metrics.PathRequests.Inc(metrics.OkSuccess)
	return pathReplyToPaths(reply.(*Pld).PathReply, dst)
}

func (c *conn) ASInfo(ctx context.Context, ia addr.IA) (*ASInfoReply, error) {
	roundTripper, err := c.ctxAwareConnect(ctx)
	if err != nil {
		metrics.ASInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	defer roundTripper.Close(ctx)
	pld, err := roundTripper.Request(
		ctx,
		&Pld{
			Which: proto.SCIONDMsg_Which_asInfoReq,
			AsInfoReq: &ASInfoReq{
				Isdas: ia.IAInt(),
			},
		},
		nil,
	)
	if err != nil {
		metrics.ASInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get ASInfo", err)
	}
	metrics.ASInfos.Inc(metrics.OkSuccess)
	return pld.(*Pld).AsInfoReply, nil
}

func (c *conn) IFInfo(ctx context.Context, ifs []common.IFIDType) (*IFInfoReply, error) {
	roundTripper, err := c.ctxAwareConnect(ctx)
	if err != nil {
		metrics.IFInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	defer roundTripper.Close(ctx)
	pld, err := roundTripper.Request(
		ctx,
		&Pld{
			Which: proto.SCIONDMsg_Which_ifInfoRequest,
			IfInfoRequest: &IFInfoRequest{
				IfIDs: ifs,
			},
		},
		nil,
	)
	if err != nil {
		metrics.IFInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get IFInfo", err)
	}
	metrics.IFInfos.Inc(metrics.OkSuccess)
	return pld.(*Pld).IfInfoReply, nil
}

func (c *conn) SVCInfo(ctx context.Context,
	svcTypes []proto.ServiceType) (*ServiceInfoReply, error) {

	roundTripper, err := c.ctxAwareConnect(ctx)
	if err != nil {
		metrics.SVCInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	defer roundTripper.Close(ctx)
	pld, err := roundTripper.Request(
		ctx,
		&Pld{
			Which: proto.SCIONDMsg_Which_serviceInfoRequest,
			ServiceInfoRequest: &ServiceInfoRequest{
				ServiceTypes: svcTypes,
			},
		},
		nil,
	)
	if err != nil {
		metrics.SVCInfos.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to get SVCInfo", err)
	}
	metrics.SVCInfos.Inc(metrics.OkSuccess)
	return pld.(*Pld).ServiceInfoReply, nil
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

	roundTripper, err := c.ctxAwareConnect(ctx)
	if err != nil {
		metrics.Revocations.Inc(errorToPrometheusLabel(err))
		return nil, serrors.Wrap(ErrUnableToConnect, err)
	}
	defer roundTripper.Close(ctx)
	reply, err := roundTripper.Request(
		ctx,
		&Pld{
			Which: proto.SCIONDMsg_Which_revNotification,
			RevNotification: &RevNotification{
				SRevInfo: sRevInfo,
			},
		},
		nil,
	)
	if err != nil {
		metrics.Revocations.Inc(errorToPrometheusLabel(err))
		return nil, serrors.WrapStr("[sciond-API] Failed to send RevNotification", err)
	}
	metrics.Revocations.Inc(metrics.OkSuccess)
	return reply.(*Pld).RevReply, nil
}

func (c *conn) Close(_ context.Context) error {
	return nil
}

func dial(ctx context.Context, socketName string) (*disp.Dispatcher, error) {
	rConn, err := reliable.Dial(ctx, socketName)
	if err != nil {
		return nil, err
	}
	return disp.New(
		rConn,
		&Adapter{},
		log.Root(),
	), nil
}

// GetDefaultSCIONDPath return default sciond path for a given IA
func GetDefaultSCIONDPath(ia *addr.IA) string {
	if ia == nil || ia.IsZero() {
		return DefaultSCIONDPath
	}
	return fmt.Sprintf("/run/shm/sciond/sd%s.sock", ia.FileFmt(false))
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
