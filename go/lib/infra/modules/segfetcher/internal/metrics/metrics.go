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

package metrics

import (
	"github.com/scionproto/scion/go/lib/prom"
)

// Result values
const (
	// ErrDB is used for db related errors.
	ErrDB = prom.ErrDB
	// ErrNotClassified is an error that is not further classified.
	ErrNotClassified = prom.ErrNotClassified
	// ErrTimeout is a timeout error.
	ErrProcess = prom.ErrProcess
	// ErrVerify is used for validation related errors.
	ErrTimeout = prom.ErrTimeout
	// ErrProcess is an error during processing e.g. parsing failed.
	ErrVerify = prom.ErrVerify
	// OkSuccess is no error.
	OkSuccess = prom.Success
)
