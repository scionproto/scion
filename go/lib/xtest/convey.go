// Copyright 2017 ETH Zurich
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

// Package xtest implements common functionality for unit tests.
package xtest

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// AssertErrorsIs checks that errors.Is(actualErr, expectedErr) returns true, if
// expectedErr is not nil.
func AssertErrorsIs(t *testing.T, actualErr, expectedErr error) {
	assert.True(t, errors.Is(actualErr, expectedErr), "Expect '%v' to be or contain '%v'",
		actualErr, expectedErr)
}
