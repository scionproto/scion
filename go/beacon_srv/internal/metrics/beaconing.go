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
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	// BcnNew indicated beacon inserted for the first time.
	BcnNew = "ok_new"
	// BcnRenew indicates existing beacon in db was update.
	BcnRenew = "ok_renew"
	// BcnFiltered indicates bnacon was filtered.
	BcnFiltered = "ok_filtered"

	// ErrProcess indicates an error during processing.
	ErrProcess = prom.ErrProcess
	// ErrPrefiltered indicates that beacon failed at pre-filtering.
	ErrPrefiltered = prom.ErrProcess
	// ErrVerify indicates that incoming beacon wasn't verified.
	ErrVerify = prom.ErrVerify
	// ErrInsert indicated that incoming beacon couldn't be inserted.
	ErrInsert = prom.ErrDB
)

// BeaconingLabels is used by clients to pass in a safe way labels
// values to prometheus metric types (e.g. counter).
type BeaconingLabels struct {
	InIfID  common.IFIDType
	NeighAS addr.IA
	Result  string
}

// Labels returns the name of the labels in correct order.
func (l BeaconingLabels) Labels() []string {
	return []string{"in_if_id", "neigh_as", prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l BeaconingLabels) Values() []string {
	return []string{l.InIfID.String(), l.NeighAS.String(), l.Result}
}

type beaconing struct {
	in prometheus.CounterVec
}

func newBeaconing() beaconing {
	sub := "beaconing"
	labels := BeaconingLabels{}.Labels()

	return beaconing{
		in: *prom.NewCounterVec(Namespace, sub, "receive_beacons_total",
			"Total number of received beacons.", labels),
	}
}

func (e *beaconing) Receives(l BeaconingLabels) prometheus.Counter {
	return e.in.WithLabelValues(l.Values()...)
}

// GetResultValue return result label value given insert stats.
func GetResultValue(s beacon.InsertStats) string {
	switch {
	case s.Updated > s.Inserted:
		return BcnRenew
	case s.Updated == s.Inserted && s.Updated == 0:
		return BcnFiltered
	default:
		return BcnNew
	}
}
