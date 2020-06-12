// Copyright 2020 Anapaya Systems
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

package handler

import (
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/pkg/cs/trust/internal/metrics"
)

// AckNotFound is sent as the error description if the crypto material is
// not found.
const AckNotFound string = "not found"

var (
	errWrongMsgType     = serrors.New("wrong message type")
	errNoResponseWriter = serrors.New("no response writer")
)

func setHandlerMetric(span opentracing.Span, l metrics.HandlerLabels, err error) {
	metrics.Handler.Request(l).Inc()
	tracing.ResultLabel(span, l.Result)
	tracing.Error(span, err)
}
