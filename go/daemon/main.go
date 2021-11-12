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

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	_ "net/http/pprof"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	promgrpc "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	segfetchergrpc "github.com/scionproto/scion/go/lib/infra/modules/segfetcher/grpc"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	"github.com/scionproto/scion/go/pkg/daemon"
	"github.com/scionproto/scion/go/pkg/daemon/api"
	"github.com/scionproto/scion/go/pkg/daemon/config"
	"github.com/scionproto/scion/go/pkg/daemon/fetcher"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hpgrpc "github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	sdpb "github.com/scionproto/scion/go/pkg/proto/daemon"
	"github.com/scionproto/scion/go/pkg/service"
	"github.com/scionproto/scion/go/pkg/storage"
	pathstoragemetrics "github.com/scionproto/scion/go/pkg/storage/path/metrics"
	truststoragemetrics "github.com/scionproto/scion/go/pkg/storage/trust/metrics"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "SCION Daemon",
		Main:       realMain,
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      globalCfg.General.Topology(),
		Reload:    app.SIGHUPChannel(ctx),
		Validator: &topology.DefaultValidator{},
		Metrics:   loaderMetrics(),
	})
	if err != nil {
		return serrors.WrapStr("creating topology loader", err)
	}
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})

	closer, err := daemon.InitTracer(globalCfg.Tracing, globalCfg.General.ID)
	if err != nil {
		return serrors.WrapStr("initializing tracer", err)
	}
	defer closer.Close()

	revCache := storage.NewRevocationStorage()
	pathDB, err := storage.NewPathStorage(globalCfg.PathDB)
	if err != nil {
		return serrors.WrapStr("initializing path storage", err)
	}
	pathDB = pathstoragemetrics.WrapDB(pathDB, pathstoragemetrics.Config{
		Driver: string(storage.BackendSqlite),
	})
	defer pathDB.Close()
	defer revCache.Close()
	cleaner := periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments"),
		300*time.Second, 295*time.Second)
	defer cleaner.Stop()
	rcCleaner := periodic.Start(revcache.NewCleaner(revCache, "sd_revocation"),
		10*time.Second, 10*time.Second)
	defer rcCleaner.Stop()

	dialer := &libgrpc.TCPDialer{
		SvcResolver: func(dst addr.HostSVC) []resolver.Address {
			if base := dst.Base(); base != addr.SvcCS {
				panic("Unsupported address type, implementation error?")
			}
			targets := []resolver.Address{}
			for _, entry := range topo.ControlServiceAddresses() {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
	}

	trustDB, err := storage.NewTrustStorage(globalCfg.TrustDB)
	if err != nil {
		return serrors.WrapStr("initializing trust database", err)
	}
	defer trustDB.Close()
	trustDB = truststoragemetrics.WrapDB(trustDB, truststoragemetrics.Config{
		Driver: string(storage.BackendSqlite),
		QueriesTotal: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Name: "trustengine_db_queries_total",
				Help: "Total queries to the database",
			},
			[]string{"driver", "operation", prom.LabelResult},
		),
	})
	engine, err := daemon.TrustEngine(globalCfg.General.ConfigDir, topo.IA(), trustDB, dialer)
	if err != nil {
		return serrors.WrapStr("creating trust engine", err)
	}
	engine.Inspector = trust.CachingInspector{
		Inspector:          engine.Inspector,
		Cache:              globalCfg.TrustEngine.Cache.New(),
		CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
		MaxCacheExpiration: globalCfg.TrustEngine.Cache.Expiration,
	}
	trcLoader := periodic.Start(periodic.Func{
		Task: func(ctx context.Context) {
			trcDirs := filepath.Join(globalCfg.General.ConfigDir, "certs")
			res, err := trust.LoadTRCs(ctx, trcDirs, trustDB)
			if err != nil {
				log.SafeInfo(log.FromCtx(ctx), "TRC loading failed", "err", err)
			}
			if len(res.Loaded) > 0 {
				log.SafeInfo(log.FromCtx(ctx), "Loaded TRCs from disk", "trcs", res.Loaded)
			}
		},
		TaskName: "daemon_trc_loader",
	}, 10*time.Second, 10*time.Second)
	defer trcLoader.Stop()

	listen := daemon.APIAddress(globalCfg.SD.Address)
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return serrors.WrapStr("listening", err)
	}

	hpGroups, err := hiddenpath.LoadHiddenPathGroups(globalCfg.SD.HiddenPathGroups)
	if err != nil {
		return serrors.WrapStr("loading hidden path groups", err)
	}
	var requester segfetcher.RPC = &segfetchergrpc.Requester{
		Dialer: dialer,
	}
	if len(hpGroups) > 0 {
		requester = &hpgrpc.Requester{
			RegularLookup: requester,
			HPGroups:      hpGroups,
			Dialer:        dialer,
		}
	}

	createVerifier := func() infra.Verifier {
		if globalCfg.SD.DisableSegVerification {
			return acceptAllVerifier{}
		}
		return compat.Verifier{Verifier: trust.Verifier{
			Engine:             engine,
			Cache:              globalCfg.TrustEngine.Cache.New(),
			CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
			MaxCacheExpiration: globalCfg.TrustEngine.Cache.Expiration,
		}}
	}

	server := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	sdpb.RegisterDaemonServiceServer(server, daemon.NewServer(
		daemon.ServerConfig{
			IA:       topo.IA(),
			MTU:      topo.MTU(),
			Topology: topo,
			Fetcher: fetcher.NewFetcher(
				fetcher.FetcherConfig{
					IA:         topo.IA(),
					MTU:        topo.MTU(),
					Core:       topo.Core(),
					NextHopper: topo,
					RPC:        requester,
					PathDB:     pathDB,
					Inspector:  engine,
					Verifier:   createVerifier(),
					RevCache:   revCache,
					Cfg:        globalCfg.SD,
				},
			),
			Engine:   engine,
			RevCache: revCache,
		},
	))

	promgrpc.Register(server)

	var cleanup app.Cleanup
	g.Go(func() error {
		defer log.HandlePanic()
		if err := server.Serve(listener); err != nil {
			return serrors.WrapStr("serving gRPC API", err, "addr", listen)
		}
		return nil
	})
	cleanup.Add(func() error { server.GracefulStop(); return nil })

	if globalCfg.API.Addr != "" {
		r := chi.NewRouter()
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins: []string{"*"},
		}))
		server := api.Server{
			Config:   service.NewConfigStatusPage(globalCfg).Handler,
			Info:     service.NewInfoStatusPage().Handler,
			LogLevel: service.NewLogLevelStatusPage().Handler,
		}
		log.Info("Exposing API", "addr", globalCfg.API.Addr)
		h := api.HandlerFromMuxWithBaseURL(&server, r, "/api/v1")
		mgmtServer := &http.Server{
			Addr:    globalCfg.API.Addr,
			Handler: h,
		}
		g.Go(func() error {
			defer log.HandlePanic()
			err := mgmtServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return serrors.WrapStr("serving service management API", err)
			}
			return nil
		})
		cleanup.Add(mgmtServer.Close)
	}

	// Start HTTP endpoints.
	statusPages := service.StatusPages{
		"info":      service.NewInfoStatusPage(),
		"config":    service.NewConfigStatusPage(globalCfg),
		"log/level": service.NewLogLevelStatusPage(),
		"topology":  service.NewTopologyStatusPage(topo),
	}
	if err := statusPages.Register(http.DefaultServeMux, globalCfg.General.ID); err != nil {
		return serrors.WrapStr("registering status pages", err)
	}

	g.Go(func() error {
		defer log.HandlePanic()
		return globalCfg.Metrics.ServePrometheus(errCtx)
	})

	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})

	return g.Wait()
}

type acceptAllVerifier struct{}

func (acceptAllVerifier) Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	return nil, nil
}

func (v acceptAllVerifier) WithServer(net.Addr) infra.Verifier {
	return v
}

func (v acceptAllVerifier) WithIA(addr.IA) infra.Verifier {
	return v
}

func loaderMetrics() topology.LoaderMetrics {
	updates := prom.NewCounterVec("", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(updates).With(prom.LabelResult, "err_validate"),
		ReadErrors:       metrics.NewPromCounter(updates).With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec("", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(updates).With(prom.LabelResult, prom.Success),
	}
}
