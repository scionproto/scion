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

// Metrics namespaces for control service subcomponents.
const (
	CSNamespace = "cs"
	BSNamespace = "bs"
	PSNamespace = "ps"
)

// Labels values.
const (
	// DstBR indicates the destination to be Border Router.
	DstBR = "br"
	// DstPS indicates the destination to be Path Server.
	DstPS = "ps"

	// ErrDB indicates an error during validation.
	ErrDB = prom.ErrDB
	// ErrCreate indicates an error during creation.
	ErrCreate = "err_create"
	// ErrParse indicates an error during processing.
	ErrParse = prom.ErrParse
	// ErrProcess indicates an error during processing.
	ErrProcess = prom.ErrProcess
	// ErrPrefilter indicates an error during pre-filtering.
	ErrPrefilter = "err_prefilter"
	// ErrVerify indicates an error during verification.
	ErrVerify = prom.ErrVerify
	// ErrSend indicates an error during verification.
	ErrSend = "err_send"
	// ErrInternal indicates an internal problem (likely a code bug).
	ErrInternal = prom.ErrInternal
	// ErrCrypto indicates a problem with crypto.
	ErrCrypto = prom.ErrCrypto
	// ErrTimeout indicates a timeout error.
	ErrTimeout = prom.ErrTimeout
	// ErrNetwork indicates a problem with the network.
	ErrNetwork = prom.ErrNetwork
	// ErrNotClassified indicates an error that is not further classified.
	ErrNotClassified = prom.ErrNotClassified
	// ErrNoPath indicates no path is available to send a message.
	ErrNoPath = "err_nopath"

	// OkFiltered indicates beacon was filtered by policy.
	OkFiltered = "ok_filtered"
	// OkNew indicates beacon was inserted for the first time.
	OkNew = "ok_new"
	// OkOld indicates that a beacon with older timestamp was received
	// and therefore it was not inserted or updated in db.
	OkOld = "ok_old"
	// OkUpdated indicates existing beacon in db was updated.
	OkUpdated = "ok_updated"
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

	// RevNew indicates a new issued revocation.
	RevNew = "new"
	// RevRenew indicates a renew of an already issued revocation.
	RevRenew = "renew"
	// RevFromCtrl indicates that revocation was sent control payload.
	RevFromCtrl = "ctrl"

	// Success indicates a successful result.
	Success = prom.Success
)

var (
	// Beaconing is the single-instance struct to get prometheus metrics or counters.
	Beaconing beaconing
	// Ifstate is the single-instance struct to get prometheus metrics or counters.
	Ifstate ifstate
	// Keepalive is the single-instance struct to get keepalive prometheus counters.
	Keepalive exporter
	// Originator is the single-instance struct to get prometheus counters.
	Originator originator
	// Propagator is the single-instance struct to get prometheus metrics or counters.
	Propagator propagator
	// Revocation is the single-instance struct to get prometheus counters.
	Revocation exporterR
	// Registrar is the single-instance struct to get prometheus metrics or counters.
	Registrar registrar
	// Registrations contains metrics for segments registrations.
	Registrations Registration
	// Requests contains metrics for segments requests.
	Requests Request
	// Sync contains metrics for segment synchronization.
	Sync sync
	// PSRevocation contains metrics for revocations.
	PSRevocation revocation
)

// InitBSMetrics initializes the metrics used by BS modules.
func InitBSMetrics() {
	Beaconing = newBeaconing()
	Ifstate = newIfstate()
	Keepalive = newKeepalive()
	Originator = newOriginator()
	Propagator = newPropagator()
	Revocation = newRevocation()
	Registrar = newRegistrar()
}

// InitPSMetrics initializes the metrics used by PS modules.
func InitPSMetrics() {
	Registrations = newRegistration()
	Requests = newRequests()
	Sync = newSync()
	PSRevocation = psNewRevocation()
}

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
