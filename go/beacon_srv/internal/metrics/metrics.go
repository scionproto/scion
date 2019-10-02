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

// Namespace is the metrics namespace for the beacon server.
const Namespace = "bs"

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

	// OkFiltered indicates beacon was filtered by policy.
	OkFiltered = "ok_filtered"
	// OkNew indicates beacon was inserted for the first time.
	OkNew = "ok_new"
	// OkOld indicates that a beacon with older timestamp was received
	// and therefore it was not inserted or updated in db.
	OkOld = "ok_old"
	// OkUpdated indicates existing beacon in db was updated.
	OkUpdated = "ok_updated"

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
	Beaconing = newBeaconing()
	// Ifstate is the single-instance struct to get prometheus metrics or counters.
	Ifstate = newIfstate()
	// Keepalive is the single-instance struct to get keepalive prometheus counters.
	Keepalive = newKeepalive()
	// Propagator is the single-instance struct to get prometheus metrics or counters.
	Propagator = newPropagator()
	// Revocation is the single-instance struct to get prometheus counters.
	Revocation = newRevocation()
	// Registrar is the single-instance struct to get prometheus metrics or counters.
	Registrar = newRegistrar()
)
