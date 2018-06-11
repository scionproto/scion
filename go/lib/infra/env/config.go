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

package env

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"unsafe"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	// Default max size of log files in MiB
	DefaultLoggingFileSize = 50
	// Default max age of log file in days
	DefaultLoggingFileMaxAge = 7
	// Default file name for topology file (only the last element of the path)
	DefaultTopologyName = "topology.json"
)

type Config struct {
	General struct {
		// ID is the SCION element ID. This is used to choose the relevant
		// portion of the topology file for some services.
		ID string
		// IAString is the string representation of IA.
		IAString string `toml:"IA"`
		// IA is the home AS.
		IA addr.IA

		// ConfigDir for loading extra files (currently, only topology.json)
		ConfigDir string
		// TopologyName is the file path for the local topology JSON file.
		TopologyName string `toml:"Topology"`
		// Topology is the loaded topology file.
		Topology *topology.Topo `toml:"-"`

		// BindString is the string representation of Bind.
		BindString string `toml:"Bind"`
		// Bind is the local address to listen on for SCION messages, and to
		// send out message to other nodes (unless Public is also set, in which
		// case that address is used for sending out messages).
		Bind *snet.Addr `toml:"-"`
		// PublicString is the string representation of Public.
		PublicString string `toml:"Public"`
		// Public is the preferred local address to use as source when sending
		// messages to other SCION nodes. If empty, Bind is used instead.
		Public *snet.Addr `toml:"-"`

		// TrustDB is the database for trust information. If a file already
		// exists, it is treated as initial trust information. If a file does
		// not exist, it is created from the initial information found under
		// directory/certs (not implemented yet).
		TrustDB string
	}

	Logging struct {
		File struct {
			// Path is the location of the logging file.
			Path string
			// Level of file logging. If unset, no file logging is performed.
			Level string
			// Size is the max size of log file in MiB (default 50)
			Size uint
			// Max age of log file in days (default 7)
			MaxAge uint
			// FlushInterval specifies how frequently to flush to the log file,
			// in seconds
			FlushInterval int
		}

		Console struct {
			// Level of console logging. If unset, not console logging is
			// performed.
			Level string
		}
	}

	Metrics struct {
		// Prometheus contains the address to export prometheus metrics on. If
		// not set, metrics are not exported.
		Prometheus string
	}
}

// LoadConfig decodes the TOML config in file name and puts the result in v.
//
// Argument v must either be of type *Config, or a type that embeds Config at
// the top level. An error is returned otherwise.
func LoadConfig(w io.Writer, name string, v interface{}) error {
	// We define the above to take an interface{} because we want it to support
	// both a base *Config and a derived configuration. This frees callers from
	// including any boilerplate (e.g., multiple passes over the TOML file or
	// calling the postprocessing function manually).

	if _, err := toml.DecodeFile(name, v); err != nil {
		return err
	}

	// We need to extract the base *Config to do default data initialization on
	// it. This has to be done via reflection because the concrete type of v
	// might be a custom type which we cannot import.
	base, ok := v.(*Config)
	if !ok {
		field := reflect.ValueOf(v).Elem().FieldByName("Config")
		if field.IsValid() {
			base = (*Config)(unsafe.Pointer(field.UnsafeAddr()))
		} else {
			return common.NewBasicError("bad object type", nil)
		}
	}

	return postprocessBase(w, base)
}

// postprocessBase loads the configuration file at name. Non-critical warning messages are
// written to the writer. If w is nil, they are written to standard error.
func postprocessBase(w io.Writer, cfg *Config) error {
	if w == nil {
		w = os.Stderr
	}

	cfg.setDefaults()
	cfg.setFiles()

	// Override with values from the topology file
	topo, err := topology.LoadFromFile(cfg.General.TopologyName)
	if err != nil {
		return err
	}
	cfg.General.Topology = topo

	var publicAddress, bindAddress *snet.Addr
	topoAddress := getAddress(cfg.General.ID, topo)
	if topoAddress != nil {
		bindAddress = getBindSnetAddress(topo.ISD_AS, topoAddress)
		publicAddress = getPublicSnetAddress(topo.ISD_AS, topoAddress)
		if publicAddress == nil {
			publicAddress = bindAddress
		}
	}

	if cfg.General.PublicString != "" {
		if publicAddress != nil {
			// If topo file also specifies this, warn the user that it is ignored
			fmt.Fprintf(w, "Warning: Discarding config general.public=%v because value "+
				"was also found in topology file\n", cfg.General.PublicString)
			cfg.General.PublicString = publicAddress.String()
		} else {
			// Try to initialize from config file
			publicAddress, err = snet.AddrFromString(cfg.General.PublicString)
			if err != nil {
				return err
			}
		}
	}
	cfg.General.Public = publicAddress

	if cfg.General.BindString != "" {
		if bindAddress != nil {
			fmt.Fprintf(w, "Warning: Discarding config general.bind=%v because value "+
				"was also found in topology file\n", cfg.General.BindString)
			cfg.General.BindString = bindAddress.String()
		} else {
			bindAddress, err = snet.AddrFromString(cfg.General.BindString)
			if err != nil {
				return err
			}
		}
	}
	cfg.General.Bind = bindAddress

	return nil
}

// setDefaults populates unset fields in cfg to their default values (if they
// have one).
func (cfg *Config) setDefaults() {
	if cfg.Logging.File.Size == 0 {
		cfg.Logging.File.Size = DefaultLoggingFileSize
	}
	if cfg.Logging.File.MaxAge == 0 {
		cfg.Logging.File.MaxAge = DefaultLoggingFileMaxAge
	}
}

// setFiles determines the values for extra config files (e.g., topology.json).
func (cfg *Config) setFiles() error {
	if cfg.General.ConfigDir != "" {
		info, err := os.Stat(cfg.General.ConfigDir)
		switch {
		case err != nil:
			return err
		case !info.IsDir():
			return common.NewBasicError(
				fmt.Sprintf("%v is not a directory", cfg.General.ConfigDir), nil)
		default:
			// Fill in file names, but do not override specifics
			if cfg.General.TopologyName == "" {
				cfg.General.TopologyName = filepath.Join(cfg.General.ConfigDir, DefaultTopologyName)
			}
		}
	}
	return nil
}

// getAddress extracts the address portion of the topo file for the specified id.
func getAddress(id string, topo *topology.Topo) *topology.TopoAddr {
	addressMaps := []map[string]topology.TopoAddr{
		topo.BS, topo.CS, topo.PS, topo.SB, topo.RS, topo.DS,
	}
	for _, addressMap := range addressMaps {
		if _, ok := addressMap[id]; ok {
			cp := addressMap[id]
			return &cp
		}
	}
	return nil
}

func getPublicSnetAddress(ia addr.IA, topoAddr *topology.TopoAddr) *snet.Addr {
	// snet only supports udp4 for now
	info := topoAddr.PublicAddrInfo(overlay.UDPIPv4)
	return snetAddressFromAddrInfo(ia, info)
}

func getBindSnetAddress(ia addr.IA, topoAddr *topology.TopoAddr) *snet.Addr {
	// snet only supports udp4 for now
	info := topoAddr.BindAddrInfo(overlay.UDPIPv4)
	return snetAddressFromAddrInfo(ia, info)
}

func snetAddressFromAddrInfo(ia addr.IA, info *topology.AddrInfo) *snet.Addr {
	if info == nil {
		return nil
	}
	return &snet.Addr{
		IA:     ia,
		Host:   addr.HostFromIP(info.IP),
		L4Port: uint16(info.L4Port),
	}
}
