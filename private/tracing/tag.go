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

package tracing

import (
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

// ResultLabel sets the operation result label on the span.
func ResultLabel(span opentracing.Span, label string) {
	span.SetTag("result.label", label)
}

// Error sets the 'error' and 'error.msg' tags according to the provided error.
func Error(span opentracing.Span, err error) {
	if err != nil {
		ext.Error.Set(span, true)
		span.SetTag("error.msg", err)
	}
}

// Component sets the 'component' tag according to the provided value.
func Component(span opentracing.Span, component string) {
	ext.Component.Set(span, component)
}
