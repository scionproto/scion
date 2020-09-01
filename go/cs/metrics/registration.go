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
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/proto"
)

// regResults lists all possible results for registrations.
var regResults = []string{OkRegistrationNew, OkRegiststrationUpdated, ErrParse, ErrInternal,
	ErrCrypto, ErrDB, ErrInternal, ErrTimeout}

// RegistrationLabels contains the label values for registration metrics.
type RegistrationLabels struct {
	Result string
	Type   proto.PathSegType
	Src    addr.IA
}

// Labels returns the labels.
func (l RegistrationLabels) Labels() []string {
	return []string{"result", "type", "src"}
}

// Values returns the values.
func (l RegistrationLabels) Values() []string {
	return []string{l.Result, l.Type.String(), l.Src.String()}
}

// Registration contains metrics for segments registrations. The metrics are the
// following:
// ps_registrations_total (total number of registrations)
type Registration struct {
	Registrations *prometheus.CounterVec
}

func newRegistration() Registration {
	return Registration{
		Registrations: prom.NewCounterVecWithLabels(PSNamespace, "", "registrations_total",
			fmt.Sprintf("Number of path registrations. \"result\" can be one of: [%s]",
				strings.Join(regResults, ",")),
			RegistrationLabels{}),
	}
}

// ResultsTotal returns the counter for ResultsTotal for the given counter.
func (r Registration) ResultsTotal(l RegistrationLabels) prometheus.Counter {
	return r.Registrations.WithLabelValues(l.Values()...)
}
