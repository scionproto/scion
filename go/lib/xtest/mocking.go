// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package xtest

import (
	"fmt"
	"testing"
)

// PanickingReporter is a wrapper around the *testing.T implementation of
// gomock.TestReporter which panics and logs on FatalF instead of calling
// runtime.Goexit(). This avoids deadlocks when a child goroutine fails a
// mocking constraint when using gomock.
//
// For more information, see https://github.com/golang/mock/issues/139.
type PanickingReporter struct {
	*testing.T
}

func (reporter *PanickingReporter) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}

// Callback defines an interfaces that provides a callback function that is
// mockable. A mock implementation implementing this interface can be found
// in sub-package mock_xtest.
type Callback interface {
	Call()
}
