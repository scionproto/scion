// Copyright 2026 Anapaya Systems
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

package e2e_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/testing/clab/e2e"
)

func TestPrintFailures(t *testing.T) {
	ep := func(ia string) e2e.Endpoint { return e2e.Endpoint{IA: ia} }
	fails := []e2e.Failure{
		{
			Src: ep("1-ff00:0:130"), Dst: ep("1-ff00:0:132"),
			Err:    errors.New("exit status 1"),
			Output: "PING 1-ff00:0:132\n1 packets transmitted, 0 received, 100% packet loss\n",
			Paths:  "Available paths to 1-ff00:0:132\n[0] Status: alive\n",
		},
		{
			Src: ep("1-ff00:0:110"), Dst: ep("1-ff00:0:111"),
			Err: errors.New("exit status 2"),
		},
	}
	e2e.SortFailures(fails)

	var sb strings.Builder
	e2e.PrintFailures(&sb, fails)
	assert.Equal(t, `  failures:
    1-ff00:0:110 -> 1-ff00:0:111: exit status 2
      output:
        <empty>
    1-ff00:0:130 -> 1-ff00:0:132: exit status 1
      output:
        PING 1-ff00:0:132
        1 packets transmitted, 0 received, 100% packet loss
      paths at failure (showpaths --extended):
        Available paths to 1-ff00:0:132
        [0] Status: alive
`, sb.String())
}

func TestPrintFailuresEmpty(t *testing.T) {
	var sb strings.Builder
	e2e.PrintFailures(&sb, nil)
	assert.Empty(t, sb.String())
}
