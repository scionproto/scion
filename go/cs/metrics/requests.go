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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/proto"
)

// RequestOkLabels contains the labels for a request that succeeded.
type RequestOkLabels struct {
	SegType proto.PathSegType
	DstISD  addr.ISD
}

// Labels returns the labels.
func (l RequestOkLabels) Labels() []string {
	return []string{"seg_type", "dst_isd"}
}

// Values returns the values.
func (l RequestOkLabels) Values() []string {
	return []string{l.SegType.String(), l.DstISD.String()}
}

// RequestLabels contains the labels for requests.
type RequestLabels struct {
	Result string
	RequestOkLabels
}

// Labels returns the labels.
func (l RequestLabels) Labels() []string {
	return append([]string{"result"}, l.RequestOkLabels.Labels()...)
}

// Values returns the values.
func (l RequestLabels) Values() []string {
	return append([]string{l.Result}, l.RequestOkLabels.Values()...)
}

// WithResult returns the labels with the modified result.
func (l RequestLabels) WithResult(result string) RequestLabels {
	l.Result = result
	return l
}

// Request is for request metrics.
type Request struct {
	Requests        *prometheus.CounterVec
	SegmentsSent    *prometheus.CounterVec
	RevocationsSent *prometheus.CounterVec
}

func newRequests() Request {
	subsystem := "requests"
	return Request{
		Requests: prom.NewCounterVecWithLabels(PSNamespace, subsystem, "total",
			"Number of segment requests total. \"result\" indicates the outcome.",
			RequestLabels{}),
		SegmentsSent: prom.NewCounterVecWithLabels(PSNamespace, subsystem, "replied_segments_total",
			"Number of segments in reply to segment requests.", RequestOkLabels{}),
		RevocationsSent: prom.NewCounterVecWithLabels(
			PSNamespace,
			subsystem,
			"replied_revocations_total",
			"Number of revocations in reply to segments requests.",
			RequestOkLabels{},
		),
	}
}

// Count returns the counter for requests total.
func (r Request) Count(l RequestLabels) prometheus.Counter {
	return r.Requests.WithLabelValues(l.Values()...)
}

// RepliedSegs returns the counter for the number of segments in a seg reply.
func (r Request) RepliedSegs(l RequestOkLabels) prometheus.Counter {
	return r.SegmentsSent.WithLabelValues(l.Values()...)
}

// RepliedRevs returns the counter for the number of revocations in a seg
// reply.
func (r Request) RepliedRevs(l RequestOkLabels) prometheus.Counter {
	return r.RevocationsSent.WithLabelValues(l.Values()...)
}

// DetermineReplyType determines which type of segments is in the reply. The
// method assumes that segs only contains one type of segments.
func DetermineReplyType(segs segfetcher.Segments) seg.Type {
	if len(segs) > 0 {
		return segs[0].Type
	}
	return 0
}
