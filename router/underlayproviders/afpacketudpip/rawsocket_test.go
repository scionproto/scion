// Copyright 2025 SCION Association
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

// IMPORTANT:
// This requires some permissions. If you need unit tests to pass, you must:
//
//	sudo setcap "cap_bpf+ep cap_net_admin+ep cap_net_raw+ep" \
//      bazel-bin/router/underlayproviders/afpacketudpip/go_default_test_/go_default_test
//
// Currently looking for a permanent solution.

package afpacketudpip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawSocket(t *testing.T) {
	// Interface #1 is lo0. Open the next one. We don't really care what it is
	// for this test.
	_, err := RawSocket(2, 50000)
	assert.NoError(t, err)
}
