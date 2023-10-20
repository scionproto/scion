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
// This code works only if the delayacct kernel feature is turned on.
// this is done by "sysctl kernel.task_delayacct=1".

//go:build linux

package processmetrics

import (
	"os"
	"strconv"
	"path/filepath"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"

	"github.com/scionproto/scion/pkg/log"
)

var (
	// These two metrics allows to infer the amount of CPU time that was available, used or not,
	// to the process:
	// wallClock time = runningTime + runnableTime + sleepingTime.
	// availableCPU = runningTime + sleepingTime
	// Therefore AvailbleTime = wallClockTime - runnableTime.
	// runningTime should be the same as uTime+sTime reported in a variety of other ways,
	// but when doing calculations, better use the two data from the same source. So, collect them
	// both.
	runningTime = prometheus.NewDesc(
		"process_running_seconds_total",
		"Time the process spend running since it started (all threads summed).",
		nil, nil,
	)
	runnableTime = prometheus.NewDesc(
		"process_runnable_seconds_total",
		"Time the process spend runnable (unscheduled) since it started (all threads summed).",
		nil, nil,
	)
	// This metric is introspective. It's trying to gauge if we're successful in collecting the
	// other two at a reasonable cost.
	tasklistUpdates = prometheus.NewDesc(
		"process_metrics_tasklist_updates_total",
		"The number of time the processmetrics collector had to recreate its list of tasks since it started.",
		nil, nil,
	)
)

// procStatCollector is a custom collector for some process-wide statistics
// that are not available in default collectors.
type procStatCollector struct {
	myPid           int
	myProcs         procfs.Procs
	myTasks         *os.File
	lastTaskCount   uint64
	lastSchedstats  map[int]procfs.ProcSchedstat
	taskListUpdates int64
}

// UpdateStat fetches the raw per-thread scheduling metrics from /proc.
// That is: from /proc/<pid>task/*/schedstat.
// This raw data is cached for Collect to pick-up and reshape
// when prometheus scrapes.
func (c *procStatCollector) updateStat() error {

	// procfs.AllThreads is expensive (lots of garbage in its wake) and often idempotent.
	// To reduce the cost, we skip doing it when we know that the threads line-up is
	// unchanged. Since Go never terminates the threads it creates, if the lineup has
	// changed, the count has changed. We can only get that from the syscall API.
	// As soon as we get the bareFd the IOs with that file become blocking. So, the thread
	// collector thread could theoretically block on the IO (not sure stating /proc results
	// in any IO wait, though).

	var taskStat syscall.Stat_t
	err := syscall.Fstat(int(c.myTasks.Fd()), &taskStat)
	if err != nil {
		return err
	}
	newCount := taskStat.Nlink - 2
	if newCount != c.lastTaskCount {
		c.taskListUpdates++
		c.myProcs, err = procfs.AllThreads(c.myPid)
		if err != nil {
			return err
		}
		c.lastTaskCount = newCount
	}

	// What we really want is to replace our map with a new map, but that would hurt the GC
	// horribly. Instead, we just delete the keys in the map, which (normally) keeps all
	// elements available for reuse. It'd be better if we could just mark entries as stale
	// and remove only the unupdated ones, but Go makes map values un-addressible. We'd need
	// to use pointers instead, which would probably make things worse. TBD.
	for pid := range c.lastSchedstats {
		delete(c.lastSchedstats, pid)
	}

	// Get a fresh set.
	for _, p := range c.myProcs {
		var oneErr error
		c.lastSchedstats[p.PID], oneErr = p.Schedstat()
		if oneErr != nil {
			err = oneErr
		}
	}

	return err
}

// Describe tells prometheus all the metrics that this collector
// collects.
func (c *procStatCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

// Collect picks the necessary raw metrics from lastSchedstat
// and derives the metrics to be returned. This is invoked whenever
// prometheus scrapes. The derivation consists mostly in unit conversions.
// Because raw metrics are very few and not expensive to get, Collect
// currently calls updateStat() every time to get the latest.
func (c *procStatCollector) Collect(ch chan<- prometheus.Metric) {
	_ = c.updateStat()

	// Sum the times of all threads.
	var ing, able uint64
	for _, p := range c.lastSchedstats {
		ing += p.RunningNanoseconds
		able += p.WaitingNanoseconds
	}
	ch <- prometheus.MustNewConstMetric(
		runningTime,
		prometheus.CounterValue,
		float64(ing)/1000000000, // Report duration in SI
	)
	ch <- prometheus.MustNewConstMetric(
		runnableTime,
		prometheus.CounterValue,
		float64(able)/1000000000, // Report duration in SI
	)
	ch <- prometheus.MustNewConstMetric(
		tasklistUpdates,
		prometheus.CounterValue,
		float64(c.taskListUpdates),
	)
}

// NewProcStatCollector creates a new collector for process statistics.
// The collector exposes those statistics to prometheus and responds
// to scraping requests. Call this only once per process or get an error.
// It is safe to ignore errors from this but prometheus may lack some
// metrics.
func NewProcStatCollector() error {	
	me := os.Getpid()
	taskPath := filepath.Join(procfs.DefaultMountPoint, strconv.Itoa(me), "task")
	taskDir, err := os.Open(taskPath)
	if err != nil {
		log.Error("NewProcStatCollector: opening /proc/pid/task/ failed",
			"pid", me, "error", err)
		return err
	}

	c := &procStatCollector{
		myPid: me,
		myTasks: taskDir,
		lastTaskCount: 0,
		lastSchedstats: make(map[int]procfs.ProcSchedstat),
	}

	err = c.updateStat()
	if err != nil {
		log.Error("NewProcStatCollector: first update failed", "error", err)
		// Ditch the broken collector. It won't do anything useful.
		return err
	}

	// It works. Register it so prometheus milks it.
	err = prometheus.Register(c)
	if err != nil {
		log.Error("NewProcStatCollector", "registration failed", err)
		return err
	}

	log.Info("NewProcStatCollector", "collector", c)
	return nil
}
