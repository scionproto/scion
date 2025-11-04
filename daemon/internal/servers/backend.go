// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package servers

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/scionproto/scion/pkg/daemon"
	"golang.org/x/sync/singleflight"

	drkey_daemon "github.com/scionproto/scion/daemon/drkey"
	"github.com/scionproto/scion/daemon/fetcher"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/topology"
)

// ConnectorBackend implements the Connector interface with the core business logic.
type ConnectorBackend struct {
	IA          addr.IA
	MTU         uint16
	Topology    Topology
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	DRKeyClient *drkey_daemon.ClientEngine

	Metrics Metrics

	foregroundPathDedupe singleflight.Group
	backgroundPathDedupe singleflight.Group
}

// LocalIA returns the local ISD-AS number.
func (c *ConnectorBackend) LocalIA(ctx context.Context) (addr.IA, error) {
	return c.IA, nil
}

// PortRange returns the beginning and end of the SCION/UDP endhost port range.
func (c *ConnectorBackend) PortRange(ctx context.Context) (uint16, uint16, error) {
	startPort, endPort := c.Topology.PortRange()
	return startPort, endPort, nil
}

// Interfaces returns the map of interface identifiers to underlay internal addresses.
func (c *ConnectorBackend) Interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	start := time.Now()
	interfaces, err := c.interfaces(ctx)
	c.Metrics.InterfacesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return interfaces, unwrapMetricsError(err)
}

func (c *ConnectorBackend) interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	result := make(map[uint16]netip.AddrPort)
	for _, ifID := range c.Topology.IfIDs() {
		nextHop := c.Topology.UnderlayNextHop(ifID)
		if nextHop == nil {
			continue
		}
		addrPort, err := netip.ParseAddrPort(nextHop.String())
		if err != nil {
			continue // Skip interfaces we can't parse
		}
		result[ifID] = addrPort
	}
	return result, nil
}

// Paths requests a set of end-to-end paths between source and destination.
func (c *ConnectorBackend) Paths(ctx context.Context, dst, src addr.IA, f daemon.PathReqFlags) ([]snet.Path, error) {
	start := time.Now()
	paths, err := c.paths(ctx, dst, src, f.Refresh)
	c.Metrics.PathsRequests.inc(
		pathReqLabels{Result: errToMetricResult(err), Dst: dst.ISD()},
		time.Since(start).Seconds(),
	)
	return paths, unwrapMetricsError(err)
}

func (c *ConnectorBackend) paths(ctx context.Context, dst, src addr.IA, refresh bool) ([]snet.Path, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancelF context.CancelFunc
		ctx, cancelF = context.WithTimeout(ctx, 10*time.Second)
		defer cancelF()
	}

	go func() {
		defer log.HandlePanic()
		c.backgroundPaths(ctx, src, dst, refresh)
	}()

	paths, err := c.fetchPaths(ctx, &c.foregroundPathDedupe, src, dst, refresh)
	if err != nil {
		log.FromCtx(ctx).Debug("Fetching paths", "err", err,
			"src", src, "dst", dst, "refresh", refresh)
		return nil, err
	}
	return paths, nil
}

func (c *ConnectorBackend) fetchPaths(
	ctx context.Context,
	group *singleflight.Group,
	src, dst addr.IA,
	refresh bool,
) ([]snet.Path, error) {
	r, err, _ := group.Do(fmt.Sprintf("%s%s%t", src, dst, refresh),
		func() (any, error) {
			return c.Fetcher.GetPaths(ctx, src, dst, refresh)
		},
	)
	// just cast to the correct type, ignore the "ok", since that can only be
	// false in case of a nil result.
	paths, _ := r.([]snet.Path)
	return paths, err
}

func (c *ConnectorBackend) backgroundPaths(origCtx context.Context, src, dst addr.IA, refresh bool) {
	backgroundTimeout := 5 * time.Second
	deadline, ok := origCtx.Deadline()
	if !ok || time.Until(deadline) > backgroundTimeout {
		// the original context is large enough no need to spin a background fetch.
		return
	}
	// We're not passing origCtx because this is a background fetch that
	// should continue even in case origCtx is cancelled.
	ctx, cancelF := context.WithTimeout(context.Background(), backgroundTimeout)
	defer cancelF()

	var spanOpts []opentracing.StartSpanOption
	if span := opentracing.SpanFromContext(origCtx); span != nil {
		spanOpts = append(spanOpts, opentracing.FollowsFrom(span.Context()))
	}
	span, ctx := opentracing.StartSpanFromContext(ctx, "fetch.paths.background", spanOpts...)
	defer span.Finish()
	//nolint:contextcheck // false positive.
	if _, err := c.fetchPaths(ctx, &c.backgroundPathDedupe, src, dst, refresh); err != nil {
		log.FromCtx(ctx).Debug("Error fetching paths (background)", "err", err,
			"src", src, "dst", dst, "refresh", refresh)
	}
}

// ASInfo requests information about AS ia.
func (c *ConnectorBackend) ASInfo(ctx context.Context, ia addr.IA) (daemon.ASInfo, error) {
	start := time.Now()
	info, err := c.asInfo(ctx, ia)
	c.Metrics.ASRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return info, unwrapMetricsError(err)
}

func (c *ConnectorBackend) asInfo(ctx context.Context, ia addr.IA) (daemon.ASInfo, error) {
	if ia.IsZero() {
		ia = c.IA
	}

	mtu := uint16(0)
	if ia.Equal(c.IA) {
		mtu = c.MTU
	}

	return daemon.ASInfo{
		IA:  ia,
		MTU: mtu,
	}, nil
}

// SVCInfo requests information about infrastructure services.
func (c *ConnectorBackend) SVCInfo(ctx context.Context, svcTypes []addr.SVC) (map[addr.SVC][]string, error) {
	start := time.Now()
	info, err := c.svcInfo(ctx, svcTypes)
	c.Metrics.ServicesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return info, unwrapMetricsError(err)
}

func (c *ConnectorBackend) svcInfo(ctx context.Context, svcTypes []addr.SVC) (map[addr.SVC][]string, error) {
	result := make(map[addr.SVC][]string)

	// For now, we only support Control services.
	if len(svcTypes) > 0 && !slices.Contains(svcTypes, addr.SVC(topology.Control)) {
		return nil, serrors.New("requested SVC type not supported",
			"requested", svcTypes)
	}

	var services []string
	for _, h := range c.Topology.ControlServiceAddresses() {
		// TODO(lukedirtwalker): build actual URI after it's defined (anapapaya/scion#3587)
		services = append(services, h.String())
	}

	if len(services) > 0 {
		result[addr.SVC(topology.Control)] = services
	}

	return result, nil
}

// RevNotification sends a RevocationInfo message to the daemon.
func (c *ConnectorBackend) RevNotification(ctx context.Context, revInfo *path_mgmt.RevInfo) error {
	start := time.Now()
	err := c.revNotification(ctx, revInfo)
	c.Metrics.InterfaceDownNotifications.inc(
		ifDownLabels{Result: errToMetricResult(err), Src: "notification"},
		time.Since(start).Seconds(),
	)
	return unwrapMetricsError(err)
}

func (c *ConnectorBackend) revNotification(ctx context.Context, revInfo *path_mgmt.RevInfo) error {
	_, err := c.RevCache.Insert(ctx, revInfo)
	if err != nil {
		log.FromCtx(ctx).Error("Inserting revocation", "err", err, "revInfo", revInfo)
		return metricsError{
			err:    serrors.Wrap("inserting revocation", err),
			result: prom.ErrDB,
		}
	}
	return nil
}

// DRKeyGetASHostKey requests a AS-Host Key.
func (c *ConnectorBackend) DRKeyGetASHostKey(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
	if c.DRKeyClient == nil {
		return drkey.ASHostKey{}, serrors.New("DRKey is not available")
	}

	key, err := c.DRKeyClient.GetASHostKey(ctx, meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.Wrap("getting AS-Host from client store", err)
	}

	return key, nil
}

// DRKeyGetHostASKey requests a Host-AS Key.
func (c *ConnectorBackend) DRKeyGetHostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error) {
	if c.DRKeyClient == nil {
		return drkey.HostASKey{}, serrors.New("DRKey is not available")
	}

	key, err := c.DRKeyClient.GetHostASKey(ctx, meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.Wrap("getting Host-AS from client store", err)
	}

	return key, nil
}

// DRKeyGetHostHostKey requests a Host-Host Key.
func (c *ConnectorBackend) DRKeyGetHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	if c.DRKeyClient == nil {
		return drkey.HostHostKey{}, serrors.New("DRKey is not available")
	}

	key, err := c.DRKeyClient.GetHostHostKey(ctx, meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("getting Host-Host from client store", err)
	}

	return key, nil
}

// Close shuts down the connector.
func (c *ConnectorBackend) Close() error {
	return nil
}
