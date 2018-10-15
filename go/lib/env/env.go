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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sciond"
	_ "github.com/scionproto/scion/go/lib/scrypto" // Make sure math/rand is seeded
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	DefaultLoggingLevel = "info"
	// Default max size of log files in MiB
	DefaultLoggingFileSize = 50
	// Default max age of log file in days
	DefaultLoggingFileMaxAge = 7
	// Default file name for topology file (only the last element of the path)
	DefaultTopologyPath = "topology.json"

	// SciondInitConnectPeriod is the default total amount of time spent
	// attempting to connect to sciond on start.
	SciondInitConnectPeriod = 20 * time.Second
)

var sighupC chan os.Signal

func init() {
	os.Setenv("TZ", "UTC")
	sighupC = make(chan os.Signal, 1)
	signal.Notify(sighupC, syscall.SIGHUP)
}

type General struct {
	// ID is the SCION element ID. This is used to choose the relevant
	// portion of the topology file for some services.
	ID string
	// ConfigDir for loading extra files (currently, only topology.json)
	ConfigDir string
	// TopologyPath is the file path for the local topology JSON file.
	TopologyPath string `toml:"Topology"`
	// Topology is the loaded topology file.
	Topology *topology.Topo `toml:"-"`
	// ReconnectToDispatcher can be set to true to enable the snetproxy reconnecter.
	ReconnectToDispatcher bool
}

// setFiles determines the values for extra config files (e.g., topology.json).
func (cfg *General) setFiles() error {
	if cfg.ConfigDir == "" {
		return nil
	}
	info, err := os.Stat(cfg.ConfigDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return common.NewBasicError(
			fmt.Sprintf("%v is not a directory", cfg.ConfigDir), nil)
	}
	// Fill in file names, but do not override specifics
	if cfg.TopologyPath == "" {
		cfg.TopologyPath = filepath.Join(cfg.ConfigDir, DefaultTopologyPath)
	}
	return nil
}

func InitGeneral(cfg *General) error {
	cfg.setFiles()
	topo, err := topology.LoadFromFile(cfg.TopologyPath)
	if err != nil {
		return err
	}
	cfg.Topology = topo
	return nil
}

// SciondClient contains information to for running snet with sciond.
type SciondClient struct {
	// Path is the sciond path. It defaults to sciond.DefaultSCIONDPath.
	Path string
	// InitialConnectPeriod is the maximum amount of time spent attempting to
	// connect to sciond on start.
	InitialConnectPeriod util.DurWrap
}

func InitSciondClient(cfg *SciondClient) {
	if cfg.Path == "" {
		cfg.Path = sciond.DefaultSCIONDPath
	}
	if cfg.InitialConnectPeriod.Duration == 0 {
		cfg.InitialConnectPeriod.Duration = SciondInitConnectPeriod
	}
}

type Env struct {
	// AppShutdownSignal is closed when the process receives a signal to close
	// (e.g., SIGTERM).
	AppShutdownSignal chan struct{}
}

func SetupEnv(reloadF func()) *Env {
	e := &Env{}
	e.setupSignals(reloadF)
	return e
}

// setupSignals sets up a goroutine that closes AppShutdownSignal on received
// SIGTERM/SIGINT signals, and calls reloadF on SIGHUP.
func (e *Env) setupSignals(reloadF func()) {
	e.AppShutdownSignal = make(chan struct{})
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		defer log.LogPanicAndExit()
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		close(e.AppShutdownSignal)
	}()
	go func() {
		defer log.LogPanicAndExit()
		for range sighupC {
			log.Info("Received config reload signal")
			if reloadF != nil {
				reloadF()
			}
		}
	}()
}

func ReloadTopology(topologyPath string) {
	topo, err := topology.LoadFromFile(topologyPath)
	if err != nil {
		log.Error("Unable to reload topology", "err", err)
		return
	}
	itopo.SetCurrentTopology(topo)
	log.Info("Reloaded topology")
}

func GetPublicSnetAddress(ia addr.IA, topoAddr *topology.TopoAddr) *snet.Addr {
	// snet only supports udp4 for now
	if topoAddr.Overlay != overlay.UDPIPv4 {
		panic("unsupported overlay")
	}
	pub := topoAddr.PublicAddr(topoAddr.Overlay)
	if pub == nil {
		return nil
	}
	return &snet.Addr{IA: ia, Host: pub}
}

func GetBindSnetAddress(ia addr.IA, topoAddr *topology.TopoAddr) *snet.Addr {
	// snet only supports udp4 for now
	if topoAddr.Overlay != overlay.UDPIPv4 {
		panic("unsupported overlay")
	}
	bind := topoAddr.BindAddr(topoAddr.Overlay)
	if bind == nil {
		return nil
	}
	return &snet.Addr{IA: ia, Host: bind}
}

type Metrics struct {
	// Prometheus contains the address to export prometheus metrics on. If
	// not set, metrics are not exported.
	Prometheus string
}

func (cfg *Metrics) StartPrometheus(fatalC chan error) {
	if cfg.Prometheus != "" {
		go func() {
			defer log.LogPanicAndExit()
			if err := http.ListenAndServe(cfg.Prometheus, nil); err != nil {
				fatalC <- common.NewBasicError("HTTP ListenAndServe error", err)
			}
		}()
	}
}

// Trust contains information that is BS, CS, PS, SD specific.
type Trust struct {
	// TrustDB is the database for trust information.
	TrustDB string
}

// Infra contains information that is BS, CS, PS specific.
type Infra struct {
	// Type must be one of BS, CS or PS.
	Type string
}
