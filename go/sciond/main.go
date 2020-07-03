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
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/spf13/cobra"

	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger/tcp"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/sciond"
	"github.com/scionproto/scion/go/pkg/sciond/config"
	"github.com/scionproto/scion/go/pkg/sciond/fetcher"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
)

func main() {
	var flags struct {
		config string
	}

	root := &cobra.Command{
		Use:           "sciond",
		Short:         "SCION Daemon",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(flags.config)
		},
	}
	root.AddCommand(
		newVersion(),
		newHelpConfig(),
	)
	root.Flags().StringVar(&flags.config, "config", "", "Configuration file (required)")
	root.MarkFlagRequired("config")

	if err := root.Execute(); err != nil {
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

	closer, err := sciond.InitTracer(cfg)
	if err != nil {
		return serrors.WrapStr("initializing tracer", err)
	}
	defer closer.Close()

	pathDB, revCache, err := pathstorage.NewPathStorage(cfg.PathDB)
	if err != nil {
		return serrors.WrapStr("initializing path storage", err)
	}
	defer pathDB.Close()
	defer revCache.Close()
	cleaner := periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments"),
		300*time.Second, 295*time.Second)
	defer cleaner.Stop()
	rcCleaner := periodic.Start(revcache.NewCleaner(revCache, "sd_revocation"),
		10*time.Second, 10*time.Second)
	defer rcCleaner.Stop()

	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		return serrors.WrapStr("initializing trust database", err)
	}
	trustDB = trustmetrics.WrapDB(string(cfg.TrustDB.Backend()), trustDB)
	defer trustDB.Close()
	engine, err := sciond.TrustEngine(cfg.General.ConfigDir, trustDB)
	if err != nil {
		return serrors.WrapStr("creating trust engine", err)
	}

	srv := sciond.Server(cfg.SD.Address, sciond.ServerCfg{
		Fetcher: fetcher.NewFetcher(
			tcp.NewClientMessenger(),
			pathDB,
			engine,
			compat.Verifier{Verifier: trust.Verifier{Engine: engine}},
			revCache,
			cfg.SD,
			itopo.Provider(),
			cfg.Features.HeaderV2,
		),
		Engine:   engine,
		PathDB:   pathDB,
		RevCache: revCache,
	})
	go func() {
		defer log.HandlePanic()
		if err := srv.ListenAndServe(); err != nil {
			fatal.Fatal(serrors.WrapStr("serving API", err, "addr", cfg.SD.Address))
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownWaitTimeout)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	sciond.StartHTTPEndpoints(cfg, cfg.Metrics)
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
