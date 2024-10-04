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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaeger "github.com/uber/jaeger-client-go"
	jaegercfg "github.com/uber/jaeger-client-go/config"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	_ "github.com/scionproto/scion/pkg/scrypto" // Make sure math/rand is seeded
	"github.com/scionproto/scion/private/config"
)

const (
	// TopologyFile is the file name for the topology file.
	TopologyFile = "topology.json"

	// StaticInfoConfigFile is the file name for the configuration file
	// used for the StaticInfo beacon extension.
	StaticInfoConfigFile = "staticInfoConfig.json"

	// SciondInitConnectPeriod is the default total amount of time spent
	// attempting to connect to the daemon on start.
	SciondInitConnectPeriod = 20 * time.Second

	// ShutdownGraceInterval is the time applications wait after issuing a
	// clean shutdown signal, before forcerfully tearing down the application.
	ShutdownGraceInterval = 5 * time.Second

	// HandlerTimeout is the time after which the http handler gives up on a request and
	// returns an error instead.
	HandlerTimeout = time.Minute
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
	// ConfigDir for loading extra files (currently, only topology.json and staticInfoConfig.json)
	ConfigDir string `toml:"config_dir,omitempty"`
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

// StaticInfoConfig return the path to the configuration file for the StaticInfo beacon extension.
func (cfg *General) StaticInfoConfig() string {
	return filepath.Join(cfg.ConfigDir, StaticInfoConfigFile)
}

var _ config.Config = (*Daemon)(nil)

// Daemon contains information for running snet with the SCION Daemon.
type Daemon struct {
	// Address of the SCION Daemon the client should connect to. Defaults to
	// 127.0.0.1:30255.
	Address string `toml:"address,omitempty"`
	// InitialConnectPeriod is the maximum amount of time spent attempting to
	// connect to the daemon on start.
	InitialConnectPeriod util.DurWrap `toml:"initial_connect_period,omitempty"`
	// FakeData can be used to replace the local daemon with a fake data source.
	// It must point to a fake daemon configuration file.
	FakeData string `toml:"fake_data,omitempty"`
}

func (cfg *Daemon) InitDefaults() {
	if cfg.Address == "" {
		cfg.Address = daemon.DefaultAPIAddress
	}
	if cfg.InitialConnectPeriod.Duration == 0 {
		cfg.InitialConnectPeriod.Duration = SciondInitConnectPeriod
	}
}

func (cfg *Daemon) Validate() error {
	if cfg.InitialConnectPeriod.Duration == 0 {
		return serrors.New("InitialConnectPeriod must not be zero")
	}
	return nil
}

func (cfg *Daemon) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, daemonSample)
}

func (cfg *Daemon) ConfigName() string {
	return "sciond_connection"
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

func (cfg *Metrics) ServePrometheus(ctx context.Context) error {
	if cfg.Prometheus == "" {
		return nil
	}
	handler := promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer,
		promhttp.HandlerFor(
			prometheus.DefaultGatherer,
			promhttp.HandlerOpts{Timeout: HandlerTimeout},
		),
	)
	http.Handle("/metrics", handler)
	log.Info("Exporting prometheus metrics", "addr", cfg.Prometheus)

	server := &http.Server{Addr: cfg.Prometheus}
	go func() {
		defer log.HandlePanic()
		<-ctx.Done()
		server.Close()
	}()
	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return serrors.Wrap("serving prometheus metrics", err)
	}
	return nil
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
		cfg.Agent = net.JoinHostPort(
			jaeger.DefaultUDPSpanServerHost,
			strconv.Itoa(jaeger.DefaultUDPSpanServerPort),
		)
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
