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

package app

import "errors"

// CodeError is an error that includes the exit code that should be returned.
type CodeError struct {
	Err  error
	Code int
}

// WithExitCode returns an error with the exit code set.
func WithExitCode(err error, code int) error {
	return CodeError{
		Err:  err,
		Code: code,
	}
}

func (e CodeError) Error() string {
	return e.Err.Error()
}

// ExitCode extracts the exit code from an error. If the error is nil, the exit
// code is zero. If the error does not wrap a CodeError, the exit code is -1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var c CodeError
	if errors.As(err, &c) {
		return c.Code
	}
	return -1
}
