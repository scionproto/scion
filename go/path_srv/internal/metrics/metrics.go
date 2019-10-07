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

// Namespace is the metrics namespace for the path server.
const Namespace = "ps"

// Group of metrics.
var (
	// Registrations contains metrics for segments registrations.
	Registrations = newRegistration()
	// Requests contains metrics for segments requests.
	Requests = newRequests()
)

// Result values
const (
	Success               = prom.Success
	RegistrationNew       = "new"
	RegiststrationUpdated = "updated"
	RequestCached         = "cached"
	RequestFetched        = "fetched"
	ErrParse              = prom.ErrParse
	ErrInternal           = prom.ErrInternal
	ErrCrypto             = prom.ErrCrypto
	ErrDB                 = prom.ErrDB
	ErrTimeout            = prom.ErrTimeout
	ErrReply              = prom.ErrReply
)

// Label values
const (
	LabelSrc    = prom.LabelSrc
	LabelResult = prom.LabelResult
	LabelType   = "type"
)
