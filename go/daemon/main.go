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
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	promgrpc "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/go/lib/addr"
	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
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
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/pkg/daemon"
	"github.com/scionproto/scion/go/pkg/daemon/config"
	"github.com/scionproto/scion/go/pkg/daemon/fetcher"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hpgrpc "github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	sdpb "github.com/scionproto/scion/go/pkg/proto/daemon"
	"github.com/scionproto/scion/go/pkg/service"
	"github.com/scionproto/scion/go/pkg/storage"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
)

func main() {
	var flags struct {
		config string
	}
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:           executable,
		Short:         "SCION Daemon",
		Example:       "  " + executable + " --config sd.toml",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(flags.config)
		},
	}
	cmd.AddCommand(
		command.NewCompletion(cmd),
		command.NewSample(cmd, command.NewSampleConfig(&config.Config{})),
		command.NewVersion(cmd),
	)
	cmd.Flags().StringVar(&flags.config, "config", "", "Configuration file (required)")
	cmd.MarkFlagRequired("config")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

const (
	shutdownWaitTimeout = 5 * time.Second
)

func run(file string) error {
	fatal.Init()
	cfg, err := setupBasic(file)
	if err != nil {
		return err
	}
	defer log.Flush()
	defer env.LogAppStopped("SD", cfg.General.ID)
	defer log.HandlePanic()
	if err := setup(cfg); err != nil {
		return err
	}

	closer, err := daemon.InitTracer(cfg.Tracing, cfg.General.ID)
	if err != nil {
		return serrors.WrapStr("initializing tracer", err)
	}
	defer closer.Close()

	revCache := storage.NewRevocationStorage()
	pathDB, err := storage.NewPathStorage(cfg.PathDB)
	if err != nil {
		return serrors.WrapStr("initializing path storage", err)
	}
	pathDB = pathdb.WithMetrics(string(storage.BackendSqlite), pathDB)
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
			targets := []resolver.Address{}
			addrs, err := itopo.Provider().Get().Multicast(dst)
			if err != nil {
				return targets
			}
			for _, entry := range addrs {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
	}

	trustDB, err := storage.NewTrustStorage(cfg.TrustDB)
	if err != nil {
		return serrors.WrapStr("initializing trust database", err)
	}
	trustDB = trustmetrics.WrapDB(string(storage.BackendSqlite), trustDB)
	defer trustDB.Close()
	engine, err := daemon.TrustEngine(cfg.General.ConfigDir, trustDB, dialer)
	if err != nil {
		return serrors.WrapStr("creating trust engine", err)
	}
	engine.Inspector = trust.CachingInspector{
		Inspector:          engine.Inspector,
		Cache:              cfg.TrustEngine.Cache.New(),
		CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
		MaxCacheExpiration: cfg.TrustEngine.Cache.Expiration,
	}

	listen := daemon.APIAddress(cfg.SD.Address)
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return serrors.WrapStr("listening", err)
	}

	hpGroups, err := hiddenpath.LoadHiddenPathGroups(cfg.SD.HiddenPathGroups)
	if err != nil {
		return serrors.WrapStr("loading hidden path groups", err)
	}
	var requester segfetcher.RPC
	requester = &segfetchergrpc.Requester{
		Dialer: dialer,
	}
	if len(hpGroups) > 0 {
		requester = &hpgrpc.Requester{
			RegularLookup: &segfetchergrpc.Requester{Dialer: dialer},
			HPGroups:      hpGroups,
			Dialer:        dialer,
		}
	}

	createVerifier := func() infra.Verifier {
		if cfg.SD.DisableSegVerification {
			return acceptAllVerifier{}
		}
		return compat.Verifier{Verifier: trust.Verifier{
			Engine:             engine,
			Cache:              cfg.TrustEngine.Cache.New(),
			CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
			MaxCacheExpiration: cfg.TrustEngine.Cache.Expiration,
		}}
	}

	server := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	sdpb.RegisterDaemonServiceServer(server, daemon.NewServer(daemon.ServerConfig{
		Fetcher: fetcher.NewFetcher(
			fetcher.FetcherConfig{
				RPC:          requester,
				PathDB:       pathDB,
				Inspector:    engine,
				Verifier:     createVerifier(),
				RevCache:     revCache,
				Cfg:          cfg.SD,
				TopoProvider: itopo.Provider(),
			},
		),
		Engine:       engine,
		PathDB:       pathDB,
		RevCache:     revCache,
		TopoProvider: itopo.Provider(),
	}))

	promgrpc.Register(server)
	go func() {
		defer log.HandlePanic()
		if err := server.Serve(listener); err != nil {
			fatal.Fatal(serrors.WrapStr("serving API", err, "addr", listen))
		}
	}()

	// Start HTTP endpoints.
	statusPages := service.StatusPages{
		"info":      service.NewInfoHandler(),
		"config":    service.NewConfigHandler(cfg),
		"topology":  itopo.TopologyHandler,
		"log/level": log.ConsoleLevel.ServeHTTP,
	}
	if err := statusPages.Register(http.DefaultServeMux, cfg.General.ID); err != nil {
		return serrors.WrapStr("registering status pages", err)
	}
	cfg.Metrics.StartPrometheus()

	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		// Deferred shutdowns for all running servers run now.
		return nil
	case <-fatal.FatalChan():
		return serrors.New("shutdown on error")
	}
}

func setupBasic(file string) (config.Config, error) {
	var cfg config.Config
	if err := libconfig.LoadFile(file, &cfg); err != nil {
		return config.Config{}, serrors.WrapStr("loading config from file", err, "file", file)
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return config.Config{}, serrors.WrapStr("initialize logging", err)
	}
	prom.ExportElementID(cfg.General.ID)
	if err := env.LogAppStarted("SD", cfg.General.ID); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func setup(cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return serrors.WrapStr("validating config", err)
	}
	topo, err := topology.FromJSONFile(cfg.General.Topology())
	if err != nil {
		return serrors.WrapStr("loading topology", err)
	}
	itopo.Init(&itopo.Config{})
	if err := itopo.Update(topo); err != nil {
		return serrors.WrapStr("unable to set initial static topology", err)
	}
	infraenv.InitInfraEnvironment(cfg.General.Topology())
	return nil
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
