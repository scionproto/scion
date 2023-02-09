// Copyright 2022 SCION Association
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

package reliable_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/sock/reliable"
)

func TestIsDispatcherError(t *testing.T) {
	cases := map[string]struct {
		err      error
		expected bool
	}{
		"nil": {
			err:      nil,
			expected: false,
		},
		"io.EOF": {
			err:      io.EOF,
			expected: true,
		},
		"io.EOF wrapped": {
			err:      fmt.Errorf("aha, end of the file %w", io.EOF),
			expected: true,
		},
		"syscall EPIPE": {
			err:      syscall.EPIPE,
			expected: true,
		},
		"OpError EPIPE": {
			err:      &net.OpError{Err: &os.SyscallError{Err: syscall.EPIPE}},
			expected: true,
		},
		"Wrapped OpError EPIPE": {
			err: fmt.Errorf("foo %w",
				&net.OpError{Err: &os.SyscallError{Err: syscall.ECONNRESET}}),
			expected: true,
		},
		"OpError ECONNRESET": {
			err:      &net.OpError{Err: &os.SyscallError{Err: syscall.ECONNRESET}},
			expected: true,
		},
		"OpError other errno": {
			err:      &net.OpError{Err: &os.SyscallError{Err: syscall.EACCES}},
			expected: false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			actual := reliable.IsDispatcherError(c.err)
			assert.Equal(t, c.expected, actual, c.err)
		})
	}
}
