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

package metrics_test

import (
	"testing"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/prom/promtest"
)

func TestQueryLabels(t *testing.T) {
	tests := map[string]interface{}{
		"QueryLabels":     metrics.QueryLabels{},
		"HandlerLabels":   metrics.HandlerLabels{},
		"InserterLabels":  metrics.InserterLabels{},
		"InspectorLabels": metrics.InspectorLabels{},
		"ProviderLabels":  metrics.ProviderLabels{},
		"ResolverLabels":  metrics.ResolverLabels{},
		"SignerLabels":    metrics.SignerLabels{},
		"VerifierLabels":  metrics.VerifierLabels{},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			promtest.CheckLabelsStruct(t, test)
		})
	}
}
