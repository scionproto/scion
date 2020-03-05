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

// Package env contains common command line and initialization code for SCION services.
// If something is specific to one app, it should go into that app's code and not here.
//
// During initialization, SIGHUPs are masked. To call a function on each
// SIGHUP, pass the function when calling Init.
package env

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/uber/jaeger-client-go"
	jaegercfg "github.com/uber/jaeger-client-go/config"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	_ "github.com/scionproto/scion/go/lib/scrypto" // Make sure math/rand is seeded
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// TopologyFile is the file name for the topology file.
	TopologyFile = "topology.json"

	// SciondInitConnectPeriod is the default total amount of time spent
	// attempting to connect to sciond on start.
	SciondInitConnectPeriod = 20 * time.Second

	// ShutdownGraceInterval is the time applications wait after issuing a
	// clean shutdown signal, before forcerfully tearing down the application.
	ShutdownGraceInterval = 5 * time.Second
)

var sighupC chan os.Signal

func init() {
	os.Setenv("TZ", "UTC")
	sighupC = make(chan os.Signal, 1)
	signal.Notify(sighupC, syscall.SIGHUP)
}

var _ config.Config = (*General)(nil)

type General struct {
	// ID is the SCION element ID. This is used to choose the relevant
	// portion of the topology file for some services.
	ID string `toml:"id,omitempty"`
	// ConfigDir for loading extra files (currently, only topology.json)
	ConfigDir string `toml:"config_dir,omitempty"`
	// ReconnectToDispatcher can be set to true to enable transparent dispatcher
	// reconnects.
	ReconnectToDispatcher bool `toml:"reconnect_to_dispatcher,omitempty"`
}

// InitDefaults sets the default value for Topology if not already set.
func (cfg *General) InitDefaults() {
}

func (cfg *General) Validate() error {
	if cfg.ID == "" {
		return serrors.New("no element id specified")
	}
	return cfg.checkDir()
}

// checkDir checks that the config dir is a directory.
func (cfg *General) checkDir() error {
	if cfg.ConfigDir != "" {
		info, err := os.Stat(cfg.ConfigDir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return serrors.New("config_dir is not a directory", "dir", cfg.ConfigDir)
		}
	}
	return nil
}

func (cfg *General) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(generalSample, ctx[config.ID]))
}

func (cfg *General) ConfigName() string {
	return "general"
}

// Topology returns the path to the topology file
func (cfg *General) Topology() string {
	return filepath.Join(cfg.ConfigDir, TopologyFile)
}

var _ config.Config = (*SCIONDClient)(nil)

// SCIONDClient contains information for running snet with sciond.
type SCIONDClient struct {
	// Address of the SCIOND server the client should connect to. Defaults to
	// 127.0.0.1:30255.
	Address string `toml:"address,omitempty"`
	// InitialConnectPeriod is the maximum amount of time spent attempting to
	// connect to sciond on start.
	InitialConnectPeriod util.DurWrap `toml:"initial_connect_period,omitempty"`
	// FakeData can be used to replace the local SCIOND with a fake data source.
	// It must point to a fake SCIOND configuration file.
	FakeData string `toml:"fake_data,omitempty"`
	// PathCount is the maximum number of paths returned to the user.
	PathCount uint16 `toml:"path_count,omitempty"`
}

func (cfg *SCIONDClient) InitDefaults() {
	if cfg.Address == "" {
		cfg.Address = sciond.DefaultSCIONDAddress
	}
	if cfg.InitialConnectPeriod.Duration == 0 {
		cfg.InitialConnectPeriod.Duration = SciondInitConnectPeriod
	}
}

func (cfg *SCIONDClient) Validate() error {
	if cfg.InitialConnectPeriod.Duration == 0 {
		return serrors.New("InitialConnectPeriod must not be zero")
	}
	return nil
}

func (cfg *SCIONDClient) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, sciondClientSample)
}

func (cfg *SCIONDClient) ConfigName() string {
	return "sciond_connection"
}

// SetupEnv initializes a basic environment for applications. If reloadF is not
// nil, the application will call reloadF whenever it receives a SIGHUP signal.
func SetupEnv(reloadF func()) {
	setupSignals(reloadF)
}

// setupSignals sets up a goroutine that on received SIGTERM/SIGINT signals
// informs the application that it should shut down. If reloadF is not nil,
// setupSignals also calls reloadF on SIGHUP.
func setupSignals(reloadF func()) {
	fatal.Check()
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		defer log.HandlePanic()
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		fatal.Shutdown(ShutdownGraceInterval)
	}()
	if reloadF != nil {
		go func() {
			defer log.HandlePanic()
			for range sighupC {
				log.Info("Received config reload signal")
				reloadF()
			}
		}()
	}
}

func ReloadTopology(topologyPath string) {
	topo, err := topology.FromJSONFile(topologyPath)
	if err != nil {
		log.Error("Unable to reload topology", "err", err)
		return
	}
	if err := itopo.Update(topo); err != nil {
		log.Error("Unable to set topology", "err", err)
		return
	}
	log.Info("Reloaded topology")
}

var _ config.Config = (*Metrics)(nil)

type Metrics struct {
	config.NoDefaulter
	config.NoValidator
	// Prometheus contains the address to export prometheus metrics on. If
	// not set, metrics are not exported.
	Prometheus string `toml:"prometheus,omitempty"`
}

func (cfg *Metrics) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, metricsSample)
}

func (cfg *Metrics) ConfigName() string {
	return "metrics"
}

func (cfg *Metrics) StartPrometheus() {
	fatal.Check()
	if cfg.Prometheus != "" {
		http.Handle("/metrics", promhttp.Handler())
		log.Info("Exporting prometheus metrics", "addr", cfg.Prometheus)
		go func() {
			defer log.HandlePanic()
			if err := http.ListenAndServe(cfg.Prometheus, nil); err != nil {
				fatal.Fatal(serrors.WrapStr("HTTP ListenAndServe error", err))
			}
		}()
	}
}

// Tracing contains configuration for tracing.
type Tracing struct {
	// Enabled enables tracing for this service.
	Enabled bool `toml:"enabled,omitempty"`
	// Enable debug mode.
	Debug bool `toml:"debug,omitempty"`
	// Agent is the address of the local agent that handles the reported
	// traces. (default: localhost:6831)
	Agent string `toml:"agent,omitempty"`
}

func (cfg *Tracing) InitDefaults() {
	if cfg.Agent == "" {
		cfg.Agent = fmt.Sprintf("%s:%d",
			jaeger.DefaultUDPSpanServerHost, jaeger.DefaultUDPSpanServerPort)
	}
}

func (cfg *Tracing) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, tracingSample)
}

func (cfg *Tracing) ConfigName() string {
	return "tracing"
}

// NewTracer creates a new Tracer for the given configuration. In case tracing
// is disabled this still returns noop-objects for convenience of the caller.
func (cfg *Tracing) NewTracer(id string) (opentracing.Tracer, io.Closer, error) {
	traceConfig := jaegercfg.Configuration{
		ServiceName: id,
		Disabled:    !cfg.Enabled,
		Reporter: &jaegercfg.ReporterConfig{
			LocalAgentHostPort: cfg.Agent,
		},
	}
	if cfg.Debug {
		traceConfig.Sampler = &jaegercfg.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
		}
	}
	bp := jaeger.NewBinaryPropagator(nil)
	return traceConfig.NewTracer(
		jaegercfg.Extractor(opentracing.Binary, bp),
		jaegercfg.Injector(opentracing.Binary, bp))
}

// QUIC contains configuration for control-plane speakers.
type QUIC struct {
	ResolutionFraction float64 `toml:"resolution_fraction,omitempty"`
	Address            string  `toml:"address,omitempty"`
	CertFile           string  `toml:"cert_file,omitempty"`
	KeyFile            string  `toml:"key_file,omitempty"`
}

func (cfg *QUIC) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, quicSample)
}

func (cfg *QUIC) ConfigName() string {
	return "quic"
}

func InfoHandler(w http.ResponseWriter, r *http.Request) {
	info := VersionInfo()
	inDocker, err := util.RunsInDocker()
	if err == nil {
		info += fmt.Sprintf("  In docker:     %v\n", inDocker)
	}
	info += fmt.Sprintf("  pid:           %d\n", os.Getpid())
	info += fmt.Sprintf("  euid/egid:     %d %d\n", os.Geteuid(), os.Getegid())
	info += fmt.Sprintf("  cmd line:      %q\n", os.Args)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, info)
}
