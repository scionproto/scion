// Copyright 2026 SCION Association
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

//go:build linux && (amd64 || arm64)

package afxdpudpip

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/log"
)

// Defaults for the settings that have no kernel counterpart. The kernel bounds
// its own queue by bytes and can allocate as it goes. Ours comes out of the
// router's fixed packet pool, so it stays small and has a hard total.
const (
	defaultNeighborQueueLen   = 3
	defaultNeighborQueueTotal = 64
	// Fallbacks for when /proc cannot be read. They are the kernel's own
	// defaults for the same settings.
	defaultNeighborCacheMax      = 1024
	defaultNeighborProbeInterval = time.Second
	defaultNeighborProbeAttempts = 3
)

// NeighborConfig bounds what a link's neighbor cache may hold.
type NeighborConfig struct {
	// QueueLen is the number of packets held per unresolved neighbor.
	// Further packets for that neighbor are dropped until the address turns up.
	// RFC 1122 asks for at least one, and the kernel holds about a hundred.
	QueueLen int
	// QueueTotal is the number of packets a link may hold across all of its
	// unresolved neighbors. It bounds how many pool buffers a sender aiming at
	// addresses that never resolve can pin.
	QueueTotal int
	// CacheMax is the number of neighbors a link tracks.
	// It defaults to the kernel's gc_thresh3.
	CacheMax int
	// ProbeInterval is the time between probes for an address that has not answered.
	// It defaults to the kernel's retrans_time_ms.
	ProbeInterval time.Duration
	// ProbeAttempts is how often an address is probed before the router gives up
	// and drops what is queued for it. It defaults to the kernel's mcast_solicit.
	//
	// Together with ProbeInterval it bounds how long a packet waits.
	// Without that bound a packet can be delivered long after its sender stopped
	// waiting for an answer, which is worse than not delivering it at all.
	ProbeAttempts int
}

// withDefaults fills in the unset fields. CacheMax comes from the kernel's own neighbor
// table limit, which is the closest thing to a sane value the system can tell us.
func (c NeighborConfig) withDefaults() NeighborConfig {
	if c.QueueLen <= 0 {
		c.QueueLen = defaultNeighborQueueLen
	}
	if c.QueueTotal <= 0 {
		c.QueueTotal = defaultNeighborQueueTotal
	}
	if c.QueueTotal < c.QueueLen {
		c.QueueTotal = c.QueueLen
	}
	if c.CacheMax <= 0 {
		c.CacheMax = kernelNeighborInt("gc_thresh3", defaultNeighborCacheMax)
	}
	if c.ProbeInterval <= 0 {
		ms := kernelNeighborInt("retrans_time_ms", int(defaultNeighborProbeInterval.Milliseconds()))
		c.ProbeInterval = time.Duration(ms) * time.Millisecond
	}
	if c.ProbeAttempts <= 0 {
		c.ProbeAttempts = kernelNeighborInt("mcast_solicit", defaultNeighborProbeAttempts)
	}
	return c
}

// kernelNeighborInt reads a value from the kernel's IPv4 neighbor defaults,
// for example /proc/sys/net/ipv4/neigh/default/gc_thresh3. The IPv6 table carries the
// same values (both are served by net/core/neighbour.c), so one read covers both.
func kernelNeighborInt(name string, fallback int) int {
	path := "/proc/sys/net/ipv4/neigh/default/" + name
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Debug("Reading kernel neighbor setting", "path", path, "err", err)
		return fallback
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || v <= 0 {
		log.Debug("Parsing kernel neighbor setting", "path", path, "raw", string(raw))
		return fallback
	}
	return v
}
