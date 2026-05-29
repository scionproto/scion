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

package engine

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/opentracing/opentracing-go"
	"golang.org/x/sync/singleflight"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/asinfo"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	drkey_daemon "github.com/scionproto/scion/private/drkey"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/trust"
)

// DaemonEngine contains the core daemon logic, independent of the transport layer.
// It can be used directly by in-process clients or wrapped by the gRPC server.
type DaemonEngine struct {
	IA          addr.IA
	MTU         uint16
	LocalASInfo asinfo.LocalASInfo
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	ASInspector trust.Inspector
	DRKeyClient *drkey_daemon.ClientEngine

	foregroundPathDedupe singleflight.Group
	backgroundPathDedupe singleflight.Group
}

// LocalIA returns the local ISD-AS number.
func (e *DaemonEngine) LocalIA(_ context.Context) (addr.IA, error) {
	return e.IA, nil
}

// PortRange returns the dispatched port range.
func (e *DaemonEngine) PortRange(_ context.Context) (uint16, uint16, error) {
	start, end := e.LocalASInfo.PortRange()
	return start, end, nil
}

// Interfaces returns the map of interface identifiers to the underlay internal address.
func (e *DaemonEngine) Interfaces(_ context.Context) (map[uint16]netip.AddrPort, error) {
	result := make(map[uint16]netip.AddrPort)
	topo := e.LocalASInfo
	for _, ifID := range topo.IfIDs() {
		nextHop := topo.UnderlayNextHop(ifID)
		if nextHop == nil {
			continue
		}
		result[ifID] = nextHop.AddrPort()
	}
	return result, nil
}

// Paths requests a set of end to end paths between the source and destination.
func (e *DaemonEngine) Paths(
	ctx context.Context,
	dst, src addr.IA,
	flags types.PathReqFlags,
) ([]snet.Path, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancelF context.CancelFunc
		ctx, cancelF = context.WithTimeout(ctx, 10*time.Second)
		defer cancelF()
	}
	go func() {
		defer log.HandlePanic()
		e.backgroundPaths(ctx, src, dst, flags.Refresh)
	}()
	paths, err := e.fetchPaths(ctx, &e.foregroundPathDedupe, src, dst, flags.Refresh)
	if err != nil {
		log.FromCtx(ctx).Debug(
			"Fetching paths", "err", err,
			"src", src, "dst", dst, "refresh", flags.Refresh,
		)
		return nil, err
	}
	return paths, nil
}

func (e *DaemonEngine) fetchPaths(
	ctx context.Context,
	group *singleflight.Group,
	src, dst addr.IA,
	refresh bool,
) ([]snet.Path, error) {
	r, err, _ := group.Do(
		fmt.Sprintf("%s%s%t", src, dst, refresh),
		func() (any, error) {
			return e.Fetcher.GetPaths(ctx, src, dst, refresh)
		},
	)
	paths, _ := r.([]snet.Path)
	return paths, err
}

func (e *DaemonEngine) backgroundPaths(origCtx context.Context, src, dst addr.IA, refresh bool) {
	backgroundTimeout := 5 * time.Second
	deadline, ok := origCtx.Deadline()
	if !ok || time.Until(deadline) > backgroundTimeout {
		return
	}
	ctx, cancelF := context.WithTimeout(context.Background(), backgroundTimeout)
	defer cancelF()
	var spanOpts []opentracing.StartSpanOption
	if span := opentracing.SpanFromContext(origCtx); span != nil {
		spanOpts = append(spanOpts, opentracing.FollowsFrom(span.Context()))
	}
	span, ctx := opentracing.StartSpanFromContext(ctx, "fetch.paths.background", spanOpts...)
	defer span.Finish()
	//nolint:contextcheck
	if _, err := e.fetchPaths(ctx, &e.backgroundPathDedupe, src, dst, refresh); err != nil {
		log.FromCtx(ctx).Debug(
			"Error fetching paths (background)", "err", err,
			"src", src, "dst", dst, "refresh", refresh,
		)
	}
}

// ASInfo requests information about an AS. The zero IA returns local AS info.
func (e *DaemonEngine) ASInfo(_ context.Context, ia addr.IA) (types.ASInfo, error) {
	reqIA := ia
	if reqIA.IsZero() {
		reqIA = e.IA
	}
	mtu := uint16(0)
	if reqIA.Equal(e.IA) {
		mtu = e.MTU
	}
	return types.ASInfo{
		IA:  reqIA,
		MTU: mtu,
	}, nil
}

// SVCInfo requests information about addresses and ports of infrastructure services.
func (e *DaemonEngine) SVCInfo(_ context.Context) ([]string, error) {
	var uris []string
	for _, h := range e.LocalASInfo.ControlServiceAddresses() {
		uris = append(uris, h.String())
	}
	return uris, nil
}

// NotifyInterfaceDown notifies about an interface that is down.
func (e *DaemonEngine) NotifyInterfaceDown(ctx context.Context, ia addr.IA, ifID uint64) error {
	revInfo := &path_mgmt.RevInfo{
		RawIsdas:     ia,
		IfID:         iface.ID(ifID),
		LinkType:     proto.LinkType_core,
		RawTTL:       10,
		RawTimestamp: util.TimeToSecs(time.Now()),
	}
	_, err := e.RevCache.Insert(ctx, revInfo)
	if err != nil {
		log.FromCtx(ctx).Error(
			"Inserting revocation", "err", err,
			"isd_as", ia, "if_id", ifID,
		)
		return metricsError{
			err:    serrors.Wrap("inserting revocation", err),
			result: prom.ErrDB,
		}
	}
	return nil
}

// DRKeyGetASHostKey requests an AS-Host Key.
func (e *DaemonEngine) DRKeyGetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {
	if e.DRKeyClient == nil {
		return drkey.ASHostKey{}, serrors.New("DRKey is not available")
	}
	return e.DRKeyClient.GetASHostKey(ctx, meta)
}

// DRKeyGetHostASKey requests a Host-AS Key.
func (e *DaemonEngine) DRKeyGetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {
	if e.DRKeyClient == nil {
		return drkey.HostASKey{}, serrors.New("DRKey is not available")
	}
	return e.DRKeyClient.GetHostASKey(ctx, meta)
}

// DRKeyGetHostHostKey requests a Host-Host Key.
func (e *DaemonEngine) DRKeyGetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {
	if e.DRKeyClient == nil {
		return drkey.HostHostKey{}, serrors.New("DRKey is not available")
	}
	return e.DRKeyClient.GetHostHostKey(ctx, meta)
}

type metricsError struct {
	err    error
	result string
}

func (e metricsError) Error() string {
	return e.err.Error()
}
