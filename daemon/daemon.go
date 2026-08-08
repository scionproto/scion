// Copyright 2018 ETH Zurich, Anapaya Systems
// Copyright 2025 SCION Association
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
	"io"
	"net"
	"strconv"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/daemon/grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/asinfo"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/private/engine"
	"github.com/scionproto/scion/private/drkey"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/trust"
)

// InitTracer initializes the global tracer.
func InitTracer(tracing env.Tracing, id string) (io.Closer, error) {
	tracer, trCloser, err := tracing.NewTracer(id)
	if err != nil {
		return nil, err
	}
	opentracing.SetGlobalTracer(tracer)
	return trCloser, nil
}

// ServerConfig is the configuration for the daemon API server.
type ServerConfig struct {
	IA          addr.IA
	MTU         uint16
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	Engine      trust.Engine
	LocalASInfo asinfo.LocalASInfo
	DRKeyClient *drkey.ClientEngine
	Metrics     grpc.Metrics
}

// NewServer constructs a daemon API server.
func NewServer(cfg ServerConfig) *grpc.DaemonServer {
	return &grpc.DaemonServer{
		Engine: &engine.DaemonEngine{
			IA:  cfg.IA,
			MTU: cfg.MTU,
			// TODO(JordiSubira): This will be changed in the future to fetch
			// the information from the CS instead of feeding the configuration
			// file into.
			LocalASInfo: cfg.LocalASInfo,
			Fetcher:     cfg.Fetcher,
			ASInspector: cfg.Engine.Inspector,
			RevCache:    cfg.RevCache,
			DRKeyClient: cfg.DRKeyClient,
		},
		Metrics: cfg.Metrics,
	}
}

// APIAddress returns the API address to listen on, based on the provided
// address. Addresses with missing or zero port are returned with the default
// daemon port. All other addresses are returned without modification. If the
// input is garbage, the output will also be garbage.
func APIAddress(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	switch {
	case err != nil:
		return net.JoinHostPort(listen, strconv.Itoa(daemon.DefaultAPIPort))
	case port == "0", port == "":
		return net.JoinHostPort(host, strconv.Itoa(daemon.DefaultAPIPort))
	default:
		return listen
	}
}
