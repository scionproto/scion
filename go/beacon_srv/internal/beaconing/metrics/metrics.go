// Copyright 2019 Anapaya Systems
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

package metrics

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

type result string

const (
	// Success indicates a successful result.
	Success result = "success"
	// CreateErr indicates an error during beacon creation.
	CreateErr result = "creation_err"
	// SendErr indicates an error during sending the beacon.
	SendErr result = "send_err"
	// InvalidErr indicates that incoming beacon was invalid.
	InvalidErr result = "invalid_err"
	// VerifyErr indicates that incoming beacon wasn't verified.
	VerifyErr result = "varify_err"
	// InsertErr indicated that incoming beacon couldn't be inserted.
	InsertErr result = "insert_err"
	// Prefiltered indicates that incoming beacon was prefiltered.
	Prefiltered result = "prefiltered"
)

var (
	originatorOnce sync.Once
	originator     *Originator
)

// Originator holds the originator metrics.
type Originator struct {
	totalBeacons     prometheus.CounterVec
	totalTime        prometheus.Counter
	totalInternalErr prometheus.Counter
}

// InitOriginator initializes the originator metrics and returns a handle.
func InitOriginator() *Originator {
	originatorOnce.Do(func() {
		originator = newOriginator()
	})
	return originator
}

func newOriginator() *Originator {
	ns := "beacon_originator"
	return &Originator{
		totalBeacons: *prom.NewCounterVec(ns, "", "beacons_total", "Number of beacons originated",
			[]string{"eg_ifid", "result"}),
		totalTime:        prom.NewCounter(ns, "", "time_seconds_total", "Total time spent"),
		totalInternalErr: prom.NewCounter(ns, "", "internal_errors_total", "Total internal errors"),
	}
}

// AddTotalTime adds the time since start to the total time.
func (m *Originator) AddTotalTime(start time.Time) {
	if m == nil {
		return
	}
	m.totalTime.Add(time.Since(start).Seconds())
}

// IncTotalBeacons increments the total beacon count.
func (m *Originator) IncTotalBeacons(eg common.IFIDType, res result) {
	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{"eg_ifid": ifidToString(eg), "result": string(res)}).Inc()
}

// IncInternalErr increments the internal error count.
func (m *Originator) IncInternalErr() {
	if m == nil {
		return
	}
	m.totalInternalErr.Inc()
}

func ifidToString(ifid common.IFIDType) string {
	return strconv.FormatUint(uint64(ifid), 10)
}
