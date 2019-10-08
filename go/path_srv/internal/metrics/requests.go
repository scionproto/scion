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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/proto"
)

var reqResults = []string{RequestCached, RequestFetched, ErrCrypto, ErrDB, ErrTimeout, ErrReply}

// RequestOkLabels contains the labels for a request that succeeded.
type RequestOkLabels struct {
	Type      proto.PathSegType
	CacheOnly bool
	DstISD    addr.ISD
}

// Labels returns the labels.
func (l RequestOkLabels) Labels() []string {
	return []string{"type", "cache_only", "dst_isd"}
}

// Values returns the values.
func (l RequestOkLabels) Values() []string {
	return []string{l.Type.String(), strconv.FormatBool(l.CacheOnly),
		strconv.FormatUint(uint64(l.DstISD), 10)}
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

// Request is for request metrics.
type Request struct {
	total     *prometheus.CounterVec
	replySegs *prometheus.CounterVec
	replyRevs *prometheus.CounterVec
}

func newRequests() Request {
	return Request{
		total: prom.NewCounterVec(Namespace, "", "requests_total",
			fmt.Sprintf("Number of path requests. \"result\" can be one of: [%s]",
				strings.Join(reqResults, ",")),
			RequestLabels{}.Labels()),
		replySegs: prom.NewCounterVec(Namespace, "", "requests_reply_segs_total",
			"Number of segments in reply to path request.", RequestOkLabels{}.Labels()),
		replyRevs: prom.NewCounterVec(Namespace, "", "requests_reply_revs_total",
			"Number of revocations returned in reply to path request.", RequestOkLabels{}.Labels()),
	}
}

// Total returns the counter for requests total.
func (r Request) Total(l RequestLabels) prometheus.Counter {
	return r.total.WithLabelValues(l.Values()...)
}

// ReplySegsTotal returns the counter for the number of segments in a seg reply.
func (r Request) ReplySegsTotal(l RequestOkLabels) prometheus.Counter {
	return r.replySegs.WithLabelValues(l.Values()...)
}

// ReplyRevsTotal returns the counter for the number of revocations in a seg
// reply.
func (r Request) ReplyRevsTotal(l RequestOkLabels) prometheus.Counter {
	return r.replyRevs.WithLabelValues(l.Values()...)
}
