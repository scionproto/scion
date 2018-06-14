// Copyright 2018 ETH Zurich
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

// Package env contains common command line and initialization code for SCION
// Infrastructure services. If something is specific to one app, it should go
// into that app's code and not here.
//
// During initialization, SIGHUPs are masked. To call a function on each
// SIGHUP, pass the function when calling Init.
//
// TODO(scrye): Also common stuff like trustdb initialization, messenger
// initialization and handler registration can go here. Everything that can be
// shared by infra apps, to reduce duplicated code.
package env

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	DefaultLoggingLevel = "info"
	// Default max size of log files in MiB
	DefaultLoggingFileSize = 50
	// Default max age of log file in days
	DefaultLoggingFileMaxAge = 7
	// Default file name for topology file (only the last element of the path)
	DefaultTopologyPath = "topology.json"
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
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		close(e.AppShutdownSignal)
	}()
	go func() {
		<-sighupC
		log.Info("Received config reload signal")
		if reloadF != nil {
			reloadF()
		}
	}()
}

func getPublicSnetAddress(ia addr.IA, topoAddr *topology.TopoAddr) *snet.Addr {
	// snet only supports udp4 for now
	if topoAddr.Overlay != overlay.UDPIPv4 {
		panic("unsupported overlay")
	}
	info := topoAddr.PublicAddrInfo(topoAddr.Overlay)
	return snetAddressFromAddrInfo(ia, info)
}

func getBindSnetAddress(ia addr.IA, topoAddr *topology.TopoAddr) *snet.Addr {
	// snet only supports udp4 for now
	if topoAddr.Overlay != overlay.UDPIPv4 {
		panic("unsupported overlay")
	}
	info := topoAddr.BindAddrInfo(topoAddr.Overlay)
	return snetAddressFromAddrInfo(ia, info)
}

func snetAddressFromAddrInfo(ia addr.IA, info *topology.AddrInfo) *snet.Addr {
	if info == nil {
		return nil
	}
	return &snet.Addr{
		IA:          ia,
		Host:        addr.HostFromIP(info.IP),
		L4Port:      uint16(info.L4Port),
		NextHopPort: uint16(info.OverlayPort),
	}
}

type Logging struct {
	File struct {
		// Path is the location of the logging file. If unset, no file logging
		// is performed.
		Path string
		// Level of file logging (defaults to DefaultLoggingLevel).
		Level string
		// Size is the max size of log file in MiB (defaults to DefaultLoggingFileSize)
		Size uint
		// Max age of log file in days (defaults to DefaultLoggingFileMaxAge)
		MaxAge uint
		// FlushInterval specifies how frequently to flush to the log file,
		// in seconds
		FlushInterval int
	}

	Console struct {
		// Level of console logging. If unset, no console logging is
		// performed.
		Level string
	}
}

// setDefaults populates unset fields in cfg to their default values (if they
// have one).
func (cfg *Logging) setDefaults() {
	if cfg.File.Size == 0 {
		cfg.File.Size = DefaultLoggingFileSize
	}
	if cfg.File.MaxAge == 0 {
		cfg.File.MaxAge = DefaultLoggingFileMaxAge
	}
	if cfg.File.Level == "" {
		cfg.File.Level = DefaultLoggingLevel
	}
}

// InitLogging initializes logging and sets the root logger Log.
func InitLogging(cfg *Logging) error {
	if cfg.File.Path != "" {
		err := log.SetupLogFile(
			filepath.Base(cfg.File.Path),
			filepath.Dir(cfg.File.Path),
			cfg.File.Level,
			int(cfg.File.Size),
			int(cfg.File.MaxAge),
			int(cfg.File.FlushInterval),
		)
		if err != nil {
			return err
		}
	}
	if cfg.Console.Level != "" {
		err := log.SetupLogConsole(cfg.Console.Level)
		if err != nil {
			return err
		}
	}
	return nil
}

type Metrics struct {
	// Prometheus contains the address to export prometheus metrics on. If
	// not set, metrics are not exported.
	Prometheus string
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
	// Public is the local address to listen on for SCION messages (if Bind is
	// not set), and to send out messages to other nodes.
	Public snet.Addr
	// If set, Bind is the preferred local address to listen on for SCION
	// messages.
	Bind snet.Addr
}

func InitInfra(cfg *Infra, id string, warnings io.Writer, topo *topology.Topo) error {
	var publicAddress, bindAddress *snet.Addr
	topoAddress := topo.GetTopoAddr(cfg.Type, id)
	if topoAddress != nil {
		bindAddress = getBindSnetAddress(topo.ISD_AS, topoAddress)
		publicAddress = getPublicSnetAddress(topo.ISD_AS, topoAddress)
	}
	if publicAddress != nil {
		// If both config file and topology file specify this, warn the user
		// that the config value is discarded
		if !cfg.Public.IsZero() {
			fmt.Fprintf(warnings, "Warning: Discarding address general.public=%v because config "+
				"was also found in topology file\n", cfg.Public)
		}
		cfg.Public = *publicAddress
	}
	if bindAddress != nil {
		if !cfg.Bind.IsZero() {
			// If both config file and topology file specify this, warn the user
			// that the config value is discarded
			fmt.Fprintf(warnings, "Warning: Discarding address general.bind=%v because config "+
				"was also found in topology file\n", cfg.Bind)
		}
		cfg.Bind = *bindAddress
	}
	return nil
}
