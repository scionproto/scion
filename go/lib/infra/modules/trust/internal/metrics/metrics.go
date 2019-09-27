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

// Namespace is the prometheus namespace.
const Namespace = "truststore"

// Request type strings.
const (
	TRCReq          = "trc_req"
	TRCPush         = "trc_push"
	ChainReq        = "chain_req"
	ChainPush       = "chain_push"
	SigVerification = "sig_verification"
	ASInspector     = "as_inspector"
	Load            = "load"
	App             = "application"
)

// Result type strings.
const (
	Success     = prom.Success
	OkCached    = "ok_cached"
	OkRequested = "ok_requested"
	OkExists    = "ok_exists"
	OkInserted  = "ok_inserted"

	ErrDB           = prom.ErrDB
	ErrDenied       = "err_denied"
	ErrInternal     = prom.ErrInternal
	ErrTransmit     = "err_transmit"
	ErrTimeout      = prom.ErrTimeout
	ErrValidate     = prom.ErrValidate
	ErrVerify       = prom.ErrVerify
	ErrTRC          = "err_trc"
	ErrNotFound     = "err_not_found"
	ErrNotFoundAuth = "err_not_found_auth"
)

var (
	// DB exposes the database metrics.
	DB = newDB()
	// Handler exposes the handler metrics.
	Handler = newHandler()
	// Store exposes the store metrics.
	Store = newStore()
)
