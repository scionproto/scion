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

package topology_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/topology"
)

func TestServiceTypeStringAndParse(t *testing.T) {
	serviceTypes := []topology.ServiceType{
		topology.Unknown,
		topology.Router,
		topology.Control,
		topology.Discovery,
		topology.Gateway,
		topology.HiddenSegmentLookup,
		topology.HiddenSegmentRegistration,
	}
	for _, st := range serviceTypes {
		t.Run(st.String(), func(t *testing.T) {
			assert.Equal(t, st, topology.ServiceTypeFromString(st.String()))
		})
	}
}
