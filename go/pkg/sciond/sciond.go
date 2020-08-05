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

package sciond

import (
	"context"
	"io"
	"path/filepath"

	opentracing "github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/messenger/tcp"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/sciond/fetcher"
	"github.com/scionproto/scion/go/pkg/sciond/internal/servers"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	"github.com/scionproto/scion/go/proto"
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

// TrustEngine builds the trust engine backed by the trust database.
func TrustEngine(cfgDir string, db trust.DB) (trust.Engine, error) {
	certsDir := filepath.Join(cfgDir, "certs")
	loaded, err := trust.LoadTRCs(context.Background(), certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.WrapStr("loading TRCs", err)
	}
	log.Info("TRCs loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		log.Info("Ignoring non-TRC", "file", f, "reason", r)
	}
	loaded, err = trust.LoadChains(context.Background(), certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.WrapStr("loading certificate chains",
			err)
	}
	log.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		log.Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}
	return trust.Engine{
		Inspector: trust.DBInspector{DB: db},
		Provider: trust.FetchingProvider{
			DB: db,
			Fetcher: trust.DefaultFetcher{
				RPC: tcp.NewClientMessenger(),
				IA:  itopo.Get().IA(),
			},
			Recurser: trust.LocalOnlyRecurser{},
			Router:   trust.LocalRouter{IA: itopo.Get().IA()},
		},
		DB: db,
	}, nil
}

// ServerCfg is the configuration for the API server.
type ServerCfg struct {
	Fetcher  fetcher.Fetcher
	PathDB   pathdb.PathDB
	RevCache revcache.RevCache
	Engine   trust.Engine
}

// Server constructs a API server. The caller is responsible for starting and
// shutting it down.
func Server(listen string, cfg ServerCfg) *servers.Server {
	handlers := servers.HandlerMap{
		proto.SCIONDMsg_Which_pathReq: &servers.PathRequestHandler{
			Fetcher: cfg.Fetcher,
		},
		proto.SCIONDMsg_Which_asInfoReq: &servers.ASInfoRequestHandler{
			ASInspector: cfg.Engine,
		},
		proto.SCIONDMsg_Which_ifInfoRequest:      &servers.IFInfoRequestHandler{},
		proto.SCIONDMsg_Which_serviceInfoRequest: &servers.SVCInfoRequestHandler{},
		proto.SCIONDMsg_Which_revNotification: &servers.RevNotificationHandler{
			RevCache: cfg.RevCache,
			Verifier: compat.Verifier{Verifier: trust.Verifier{Engine: cfg.Engine}},
		},
	}
	return servers.NewServer("tcp", listen, handlers)
}
