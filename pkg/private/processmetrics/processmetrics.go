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

// Package processmetrics provides a custom collector to export process-level
// metrics beyond what prometheus.ProcesssCollector offers.
// This implementation is restricted to Linux. The generic implementation
// does nothing.

//go:build linux

package processmetrics


import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"os"
)

var (
	iowaitTime = prometheus.NewDesc(
		"process_iowait_seconds_total",
		"IO wait time accumulated by the process since it started (all threads summed).",
		nil, nil,
	)
)

type procStatCollector struct {
	myPid int
	lastProcStats map[int]procfs.ProcStat
}

func (c *procStatCollector) updateStat() {
	// FIXME: ... if we can. Allthreads builds a list and it
	// ends-up on the garbage pile.
	myProcs, err := procfs.AllThreads(c.myPid)
	if err != nil {
		// TODO: make this more visible.
		return
	}
	
	// What we really want is to replace our map with a new map, but that would hurt the GC
	// horribly. Instead, we just delete the keys in the map, which (normally) keeps all
	// elements available for reuse. It'd be better if we could just mark entries as stale
	// and remove only the unupdated ones, but Go makes map values un-addressible. We'd need
	// to use pointers instead, which would probably make things worse. TBD.
	for pid := range c.lastProcStats {
		delete(c.lastProcStats, pid)
	}

	// Get a fresh set.
	for _, p := range myProcs {
		c.lastProcStats[p.PID], _ = p.Stat()
		// TODO: consider what to do if this fails
	}
}

func (c *procStatCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func (c *procStatCollector) Collect(ch chan<- prometheus.Metric) {
	c.updateStat()

	// Summ the iowait of all threads.
	var t uint64
	for _, p := range c.lastProcStats {
		t += (p.DelayAcctBlkIOTicks * 100)
	}
	ch <- prometheus.MustNewConstMetric(
		iowaitTime,
		prometheus.CounterValue,
		float64(t),
	)
}

func NewProcStatCollector() error {
	c := &procStatCollector {
		myPid: os.Getpid(),
		lastProcStats: make(map[int]procfs.ProcStat),
	}

	prometheus.MustRegister(c)
	return nil
}
