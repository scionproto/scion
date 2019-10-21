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
	// Sync contains metrics for segment synchronization.
	Sync = newSync()
	// Revocation contains metrics for revocations.
	Revocation = newRevocation()
)

// Result values
const (
	// OkSuccess is no error.
	OkSuccess = prom.Success
	// OkRegistrationNew indicates something new was registered.
	OkRegistrationNew = "ok_new"
	// OkRegiststrationUpdated indicates a registration was updated.
	OkRegiststrationUpdated = "ok_updated"
	// OkRequestCached indicates the request could be processed and the result
	// came from cache.
	OkRequestCached = "ok_cached"
	// OkRequestFetched indicates the request could be processed but the result
	// needed to be fetched from a remote server.
	OkRequestFetched = "ok_fetched"
	// ErrParse indicates a parse error.
	ErrParse = prom.ErrParse
	// ErrInternal indicates an internal problem (likely a code bug).
	ErrInternal = prom.ErrInternal
	// ErrCrypto indicates a problem with crypto.
	ErrCrypto = prom.ErrCrypto
	// ErrDB indicates a problem with the DB.
	ErrDB = prom.ErrDB
	// ErrTimeout indicates a timeout error.
	ErrTimeout = prom.ErrTimeout
	// ErrNetwork indicates a problem with the network.
	ErrNetwork = prom.ErrNetwork
	// ErrNotClassified indicates an error that is not further classified.
	ErrNotClassified = prom.ErrNotClassified
	// ErrNoPath indicates no path is available to send a message.
	ErrNoPath = "err_nopath"
)

// Revocation sources
const (
	RevSrcNotification = "notification"
	RevSrcSCMP         = "scmp"
	RevSrcPathReply    = "path_reply"
)

// Label values
const (
	LabelSrc    = prom.LabelSrc
	LabelResult = prom.LabelResult
	LabelType   = "type"
)
