// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package discovery

import (
	"context"
	"errors"
	"net"

	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/tracing"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
)

// Topology implements a service discovery server based on a topology provider.
type Topology struct {
	// Provider is used to get a topology instance.
	Provider topology.Provider

	// Requests aggregates all the incoming requests received by the handler.
	// If it is not initialized, nothing is reported.
	Requests metrics.Counter
}

// Gateways discovers gateways in this topology.
func (t Topology) Gateways(ctx context.Context,
	_ *dpb.GatewaysRequest) (*dpb.GatewaysResponse, error) {

	span := opentracing.SpanFromContext(ctx)
	labels := requestLabels{ReqType: "gateways"}
	logger := log.FromCtx(ctx)

	topo := t.Provider.Get()
	gateways, err := topo.Gateways()
	if err != nil {
		logger.Debug("Failed to list gateways", "err", err)
		t.updateTelemetry(span, labels.WithResult(prom.ErrInternal), err)
		return nil, status.Error(codes.Internal, "failed to list gateways")
	}
	reply := &dpb.GatewaysResponse{
		Gateways: make([]*dpb.Gateway, 0, len(gateways)),
	}
	for _, info := range gateways {
		// XXX(lukedirtwalker): for now we use a fixed probe port in the future
		// we can just send a different one if we need to.
		probeAddr := &net.UDPAddr{
			IP:   info.CtrlAddr.SCIONAddress.IP,
			Zone: info.CtrlAddr.SCIONAddress.Zone,
			Port: 30856,
		}
		reply.Gateways = append(reply.Gateways, &dpb.Gateway{
			ControlAddress:  info.CtrlAddr.SCIONAddress.String(),
			DataAddress:     info.DataAddr.String(),
			ProbeAddress:    probeAddr.String(),
			AllowInterfaces: info.AllowInterfaces,
		})
	}
	logger.Debug("Replied with gateways", "gateways", gateways)
	t.updateTelemetry(span, labels.WithResult(prom.Success), nil)
	return reply, nil
}

// HiddenSegmentServices discovers hidden segment services in this topology.
func (t Topology) HiddenSegmentServices(ctx context.Context,
	_ *dpb.HiddenSegmentServicesRequest) (*dpb.HiddenSegmentServicesResponse, error) {

	span := opentracing.SpanFromContext(ctx)
	labels := requestLabels{ReqType: "hidden_segment_services"}
	logger := log.FromCtx(ctx)

	topo := t.Provider.Get()
	lookups, err := topo.MakeHostInfos(topology.HiddenSegmentLookup)
	if err != nil && !errors.Is(err, topology.ErrAddressNotFound) {
		return nil, err
	}
	registration, err := topo.MakeHostInfos(topology.HiddenSegmentRegistration)
	if err != nil && !errors.Is(err, topology.ErrAddressNotFound) {
		return nil, err
	}

	response := &dpb.HiddenSegmentServicesResponse{}
	for _, l := range lookups {
		response.Lookup = append(response.Lookup, &dpb.HiddenSegmentLookupServer{
			Address: l.String(),
		})
	}
	for _, r := range registration {
		response.Registration = append(response.Registration, &dpb.HiddenSegmentRegistrationServer{
			Address: r.String(),
		})
	}

	logger.Debug("Replied with hidden segment services",
		"lookups", len(lookups), "registration", len(registration))
	t.updateTelemetry(span, labels.WithResult(prom.Success), nil)
	return response, nil
}

// RequestsLabels exposes the labels required by the Requests metric.
func (t Topology) RequestsLabels() []string {
	return []string{"req_type", prom.LabelResult}
}

func (t Topology) updateTelemetry(span opentracing.Span, l requestLabels, err error) {
	if t.Requests != nil {
		t.Requests.With(l.Expand()...).Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}

type requestLabels struct {
	ReqType string
	Result  string
}

func (l requestLabels) Expand() []string {
	return []string{
		"req_type", l.ReqType,
		prom.LabelResult, l.Result,
	}
}

func (l requestLabels) WithResult(result string) requestLabels {
	l.Result = result
	return l
}
