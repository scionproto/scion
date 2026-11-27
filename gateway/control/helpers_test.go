// Copyright 2026 SCION Association
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

package control_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/pktcls"
)

func mustCond(t *testing.T, class string) pktcls.Cond {
	t.Helper()
	c, err := pktcls.BuildClassTree(class)
	require.NoError(t, err)
	return c
}
