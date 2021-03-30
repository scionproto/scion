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

package metrics

import (
	"github.com/scionproto/scion/go/lib/prom"
)

// Namespace is the prometheus namespace.
const Namespace = "renewal"

// Signer exposes the signer metrics.
var Signer = newSigner()

// Result types
const (
	Success = prom.Success

	ErrInactive = "err_inactive"
	ErrInternal = prom.ErrInternal
	ErrKey      = "err_key"
	ErrCerts    = "err_certs"
	ErrNotFound = "err_not_found"
)
