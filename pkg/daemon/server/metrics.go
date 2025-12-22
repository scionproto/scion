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

package server

import (
	"context"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

type ConnectorMetricsWrapper struct {
	daemon.Connector
	Metrics *Metrics
}

// Note: No metrics are collected for LocalIA, PortRange and DRKey functions.

func (c *ConnectorMetricsWrapper) Interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	start := time.Now()
	interfaces, err := c.Connector.Interfaces(ctx)
	c.Metrics.InterfacesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return interfaces, unwrapMetricsError(err)
}

func (c *ConnectorMetricsWrapper) Paths(ctx context.Context, dst, src addr.IA, f daemon.PathReqFlags) ([]snet.Path, error) {
	start := time.Now()
	paths, err := c.Connector.Paths(ctx, dst, src, f)
	c.Metrics.PathsRequests.inc(
		pathReqLabels{Result: errToMetricResult(err), Dst: dst.ISD()},
		time.Since(start).Seconds(),
	)
	return paths, unwrapMetricsError(err)
}

func (c *ConnectorMetricsWrapper) ASInfo(ctx context.Context, ia addr.IA) (daemon.ASInfo, error) {
	start := time.Now()
	info, err := c.Connector.ASInfo(ctx, ia)
	c.Metrics.ASRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return info, unwrapMetricsError(err)
}

func (c *ConnectorMetricsWrapper) SVCInfo(ctx context.Context, svcTypes []addr.SVC) (map[addr.SVC][]string, error) {
	start := time.Now()
	info, err := c.Connector.SVCInfo(ctx, svcTypes)
	c.Metrics.ServicesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return info, unwrapMetricsError(err)
}

func (c *ConnectorMetricsWrapper) RevNotification(ctx context.Context, revInfo *path_mgmt.RevInfo) error {
	start := time.Now()
	err := c.Connector.RevNotification(ctx, revInfo)
	c.Metrics.InterfaceDownNotifications.inc(
		ifDownLabels{Result: errToMetricResult(err), Src: "notification"},
		time.Since(start).Seconds(),
	)
	return unwrapMetricsError(err)
}

// Labels used for metrics in the Metrics struct, those labels should be used
// for initialization.
var (
	PathsRequestsLabels              = []string{prom.LabelResult, prom.LabelDst}
	ASRequestsLabels                 = []string{prom.LabelResult}
	InterfacesRequestsLabels         = []string{prom.LabelResult}
	ServicesRequestsLabels           = []string{prom.LabelResult}
	InterfaceDownNotificationsLabels = []string{prom.LabelResult, prom.LabelSrc}
	LatencyLabels                    = []string{prom.LabelResult}
)

// Metrics can be used to inject metrics into the SCION daemon server. Each
// field may be set individually.
type Metrics struct {
	PathsRequests              RequestMetrics
	ASRequests                 RequestMetrics
	InterfacesRequests         RequestMetrics
	ServicesRequests           RequestMetrics
	InterfaceDownNotifications RequestMetrics
}

// RequestMetrics contains the metrics for a given request.
type RequestMetrics struct {
	Requests metrics.Counter
	Latency  metrics.Histogram
}

func (m RequestMetrics) inc(expander interface{ Expand() []string }, latency float64) {
	if m.Requests != nil {
		m.Requests.With(expander.Expand()...).Add(1)
	}
	if m.Latency != nil {
		m.Latency.With(expander.Expand()[:2]...).Observe(latency)
	}
}

type reqLabels struct {
	Result string
}

func (l reqLabels) Expand() []string {
	return []string{
		prom.LabelResult, l.Result,
	}
}

type pathReqLabels struct {
	Result string
	Dst    addr.ISD
}

func (l pathReqLabels) Expand() []string {
	return []string{
		prom.LabelResult, l.Result,
		prom.LabelDst, l.Dst.String(),
	}
}

type ifDownLabels struct {
	Result string
	Src    string
}

func (l ifDownLabels) Expand() []string {
	return []string{
		prom.LabelResult, l.Result,
		prom.LabelSrc, l.Src,
	}
}

type metricsError struct {
	err    error
	result string
}

func (e metricsError) Error() string {
	return e.err.Error()
}

func errToMetricResult(err error) string {
	if err == nil {
		return prom.Success
	}
	if merr, ok := err.(metricsError); ok && merr.result != "" {
		if serrors.IsTimeout(merr.err) {
			return prom.ErrTimeout
		}
		return merr.result
	}
	if serrors.IsTimeout(err) {
		return prom.ErrTimeout
	}
	return prom.ErrNotClassified
}

func unwrapMetricsError(err error) error {
	if err == nil {
		return nil
	}
	if merr, ok := err.(metricsError); ok {
		return merr.err
	}
	return err
}
