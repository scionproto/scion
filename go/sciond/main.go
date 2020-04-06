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

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger/tcp"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdbmetrics"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/config"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
	"github.com/scionproto/scion/go/sciond/internal/servers"
)

const (
	ShutdownWaitTimeout = 5 * time.Second
)

var (
	cfg config.Config
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("SD", cfg.General.ID)
	defer log.HandlePanic()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	pathDB, revCache, err := pathstorage.NewPathStorage(cfg.PathDB)
	if err != nil {
		log.Crit("Unable to initialize path storage", "err", err)
		return 1
	}
	defer pathDB.Close()
	defer revCache.Close()
	tracer, trCloser, err := cfg.Tracing.NewTracer(cfg.General.ID)
	if err != nil {
		log.Crit("Unable to create tracer", "err", err)
		return 1
	}
	defer trCloser.Close()
	opentracing.SetGlobalTracer(tracer)

	publicIP, err := net.ResolveUDPAddr("udp", cfg.SD.Address)
	if err != nil {
		log.Crit("Unable to resolve listening address", "err", err, "addr", publicIP)
		return 1
	}

	msger := tcp.NewClientMessenger(tcp.Client{TopologyProvider: itopo.Provider()})
	defer msger.CloseServer()

	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Error initializing trust database", "err", err)
		return 1
	}
	trustDB = trustdbmetrics.WithMetrics(string(cfg.TrustDB.Backend()), trustDB)
	defer trustDB.Close()
	inserter := trust.DefaultInserter{
		BaseInserter: trust.BaseInserter{DB: trustDB},
	}
	provider := trust.Provider{
		DB:       trustDB,
		Recurser: trust.LocalOnlyRecurser{},
		Resolver: trust.DefaultResolver{
			DB:       trustDB,
			Inserter: inserter,
			RPC:      trust.DefaultRPC{Msgr: msger},
			IA:       itopo.Get().IA(),
		},
		Router: trust.LocalRouter{IA: itopo.Get().IA()},
	}
	trustStore := trust.Store{
		Inspector:      trust.DefaultInspector{Provider: provider},
		CryptoProvider: provider,
		Inserter:       inserter,
		DB:             trustDB,
	}
	certsDir := filepath.Join(cfg.General.ConfigDir, "certs")
	err = trustStore.LoadCryptoMaterial(context.Background(), certsDir)
	if err != nil {
		log.Crit("Error loading crypto material", "err", err)
		return 1
	}

	handlers := servers.HandlerMap{
		proto.SCIONDMsg_Which_pathReq: &servers.PathRequestHandler{
			Fetcher: fetcher.NewFetcher(
				msger,
				pathDB,
				trustStore,
				verificationFactory{Provider: trustStore},
				revCache,
				cfg.SD,
				itopo.Provider(),
			),
		},
		proto.SCIONDMsg_Which_asInfoReq: &servers.ASInfoRequestHandler{
			ASInspector: trustStore,
		},
		proto.SCIONDMsg_Which_ifInfoRequest:      &servers.IFInfoRequestHandler{},
		proto.SCIONDMsg_Which_serviceInfoRequest: &servers.SVCInfoRequestHandler{},
		proto.SCIONDMsg_Which_revNotification: &servers.RevNotificationHandler{
			RevCache:         revCache,
			VerifierFactory:  verificationFactory{Provider: trustStore},
			NextQueryCleaner: segfetcher.NextQueryCleaner{PathDB: pathDB},
		},
	}
	cleaner := periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments"),
		300*time.Second, 295*time.Second)
	defer cleaner.Stop()
	rcCleaner := periodic.Start(revcache.NewCleaner(revCache, "sd_revocation"),
		10*time.Second, 10*time.Second)
	defer rcCleaner.Stop()
	apiServer, shutdownF := NewServer("tcp", cfg.SD.Address, handlers)
	defer shutdownF()
	StartServer(cfg.SD.Address, apiServer)
	http.HandleFunc("/config", configHandler)
	http.HandleFunc("/info", env.InfoHandler)
	http.HandleFunc("/topology", itopo.TopologyHandler)
	cfg.Metrics.StartPrometheus()
	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		// Deferred shutdowns for all running servers run now.
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

type verificationFactory struct {
	Provider trust.CryptoProvider
}

func (v verificationFactory) NewSigner(common.RawBytes, infra.SignerMeta) (infra.Signer, error) {
	return nil, serrors.New("signer generation not supported")
}

func (v verificationFactory) NewVerifier() infra.Verifier {
	return trust.NewVerifier(v.Provider)
}

func setupBasic() error {
	md, err := toml.DecodeFile(env.ConfigFile(), &cfg)
	if err != nil {
		return serrors.WrapStr("Failed to load config", err, "file", env.ConfigFile())
	}
	if len(md.Undecoded()) > 0 {
		return serrors.New("Failed to load config: undecoded keys", "undecoded", md.Undecoded())
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return serrors.WrapStr("Failed to initialize logging", err)
	}
	prom.ExportElementID(cfg.General.ID)
	return env.LogAppStarted("SD", cfg.General.ID)
}

func setup() error {
	if err := cfg.Validate(); err != nil {
		return common.NewBasicError("unable to validate config", err)
	}
	topo, err := topology.FromJSONFile(cfg.General.Topology())
	if err != nil {
		return common.NewBasicError("unable to load topology", err)
	}
	itopo.Init(&itopo.Config{})
	if err := itopo.Update(topo); err != nil {
		return common.NewBasicError("unable to set initial static topology", err)
	}
	infraenv.InitInfraEnvironment(cfg.General.Topology())
	return nil
}

func NewServer(network string, rsockPath string,
	handlers servers.HandlerMap) (*servers.Server, func()) {

	server := servers.NewServer(network, rsockPath, handlers)
	shutdownF := func() {
		ctx, cancelF := context.WithTimeout(context.Background(), ShutdownWaitTimeout)
		server.Shutdown(ctx)
		cancelF()
	}
	return server, shutdownF
}

func StartServer(address string, server *servers.Server) {
	go func() {
		defer log.HandlePanic()
		if err := server.ListenAndServe(); err != nil {
			fatal.Fatal(common.NewBasicError("ListenAndServe error", err, "address", address))
		}
	}()
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	var buf bytes.Buffer
	toml.NewEncoder(&buf).Encode(cfg)
	fmt.Fprint(w, buf.String())
}
