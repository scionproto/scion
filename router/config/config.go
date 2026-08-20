// Copyright 2019 ETH Zurich, Anapaya Systems
// Copyright 2023 SCION Association
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

// Package config defines the router's configuration file.
package config

import (
	"io"
	"runtime"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
	api "github.com/scionproto/scion/private/mgmtapi"
)

const idSample = "router-1"

type Config struct {
	General  env.General  `toml:"general,omitempty"`
	Features env.Features `toml:"features,omitempty"`
	Logging  log.Config   `toml:"log,omitempty"`
	Metrics  env.Metrics  `toml:"metrics,omitempty"`
	API      api.Config   `toml:"api,omitempty"`
	Router   RouterConfig `toml:"router,omitempty"`
}

type RouterConfig struct {
	ReceiveBufferSize     int `toml:"receive_buffer_size,omitempty"`
	SendBufferSize        int `toml:"send_buffer_size,omitempty"`
	NumProcessors         int `toml:"num_processors,omitempty"`
	NumSlowPathProcessors int `toml:"num_slow_processors,omitempty"`
	BatchSize             int `toml:"batch_size,omitempty"`
	BFD                   BFD `toml:"bfd,omitempty"`
	// TODO: These two values were introduced to override the port range for
	// configured router in the context of acceptance tests.
	// However, this introduces two sources for the port configuration.
	// We should remove this and adapt the acceptance tests.
	DispatchedPortStart *int              `toml:"dispatched_port_start,omitempty"`
	DispatchedPortEnd   *int              `toml:"dispatched_port_end,omitempty"`
	PreferredUnderlays  map[string]string `toml:"preferred_underlays,omitempty"`
	Neighbor            Neighbor          `toml:"neighbor,omitempty"`
}

// Neighbor bounds what an underlay's neighbor cache holds while it resolves
// MAC addresses. It applies to underlays that resolve addresses themselves,
// which today means udpip:afxdp. Zero values take a default, and CacheMax and
// StaleTime take theirs from the kernel's own neighbor table settings.
type Neighbor struct {
	// QueueLen is the number of packets held per unresolved neighbor.
	// Default 1, which is the minimum RFC 1122 asks for.
	QueueLen int `toml:"queue_len,omitempty"`
	// QueueTotal is the number of packets a link holds across
	// all of its unresolved neighbors. Default 64.
	QueueTotal int `toml:"queue_total,omitempty"`
	// CacheMax is the number of neighbors a link tracks.
	// Default net.ipv4.neigh.default.gc_thresh3.
	CacheMax int `toml:"cache_max,omitempty"`
	// ProbeInterval is the time between probes for an address that has not answered.
	// Default net.ipv4.neigh.default.retrans_time_ms.
	ProbeInterval util.DurWrap `toml:"probe_interval,omitempty"`
	// ProbeAttempts is how often an address is probed before the router drops
	// what is queued for it. Default net.ipv4.neigh.default.mcast_solicit.
	ProbeAttempts int `toml:"probe_attempts,omitempty"`
}

// BFD configuration. Unfortunately cannot be shared with topology.BFD
// as one is toml and the other json. Even though the semantics are identical.
type BFD struct {
	Disable               bool         `toml:"disable,omitempty"`
	DetectMult            uint8        `toml:"detect_mult,omitempty"`
	DesiredMinTxInterval  util.DurWrap `toml:"desired_min_tx_interval,omitempty"`
	RequiredMinRxInterval util.DurWrap `toml:"required_min_rx_interval,omitempty"`
}

func (cfg *RouterConfig) ConfigName() string {
	return "router"
}

func (cfg *RouterConfig) Validate() error {
	if cfg.ReceiveBufferSize < 0 {
		return serrors.New("Provided router config is invalid. ReceiveBufferSize < 0")
	}
	if cfg.SendBufferSize < 0 {
		return serrors.New("Provided router config is invalid. SendBufferSize < 0")
	}
	if cfg.BatchSize < 1 {
		return serrors.New("Provided router config is invalid. BatchSize < 1")
	}
	if cfg.NumProcessors < 0 {
		return serrors.New("Provided router config is invalid. NumProcessors < 0")
	}
	if cfg.NumSlowPathProcessors < 1 {
		return serrors.New("Provided router config is invalid. NumSlowPathProcessors < 1")
	}
	if cfg.DispatchedPortStart != nil {
		if cfg.DispatchedPortEnd == nil {
			return serrors.New("provided router config is invalid. " +
				"EndHostEndPort is nil; EndHostStartPort isn't")
		}
		if *cfg.DispatchedPortStart < 0 {
			return serrors.New("provided router config is invalid. EndHostStartPort < 0")
		}
		if *cfg.DispatchedPortEnd >= (1 << 16) {
			return serrors.New("provided router config is invalid. EndHostEndPort > 2**16 -1")
		}
		if *cfg.DispatchedPortStart > *cfg.DispatchedPortEnd {
			return serrors.New("provided router config is invalid. " +
				"EndHostStartPort > DispatchedPortEnd")
		}
	} else {
		if cfg.DispatchedPortEnd != nil {
			return serrors.New("provided router config is invalid. " +
				"EndHostStartPort is nil; EndHostEndPort isn't")
		}
	}
	return nil
}

func (cfg *RouterConfig) InitDefaults() {
	// NumProcessors is the number of goroutines used to handle the processing queue.
	// It has been observed that allowing the packet processors starve the other tasks was
	// counterproductive. We get much better results by setting two cores aside for other go
	// routines (such as for input and output). It remains to be seen if even more cores need to be
	// set aside on large core-count systems.

	if cfg.NumProcessors == 0 {
		// Do what we think is best, so in most cases there's no need for an explicit config.
		maxProcs := runtime.GOMAXPROCS(0)
		if maxProcs > 3 {
			// Two for I/Os, two or more for processing.
			cfg.NumProcessors = maxProcs - 2
		} else if maxProcs > 1 {
			// I/Os <= processing.
			cfg.NumProcessors = maxProcs - 1
		} else {
			// No choice.
			cfg.NumProcessors = maxProcs
		}
	}

	if cfg.NumSlowPathProcessors == 0 {
		cfg.NumSlowPathProcessors = 1
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 256
	}
	if cfg.BFD.DetectMult == 0 {
		cfg.BFD.DetectMult = 3
	}
	if cfg.BFD.DesiredMinTxInterval.Duration == 0 {
		cfg.BFD.DesiredMinTxInterval = util.DurWrap{Duration: 200 * time.Millisecond}
	}
	if cfg.BFD.RequiredMinRxInterval.Duration == 0 {
		cfg.BFD.RequiredMinRxInterval = util.DurWrap{Duration: 200 * time.Millisecond}
	}
	if cfg.PreferredUnderlays == nil {
		cfg.PreferredUnderlays = map[string]string{"udpip": "afxdp"}
	}
}

func (cfg *RouterConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, routerConfigSample)
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Router,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Router,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Router,
	)
}
