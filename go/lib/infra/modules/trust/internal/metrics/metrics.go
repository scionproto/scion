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

// Trust material
const (
	Chain = "chain"
	TRC   = "trc"
	ASKey = "as_key"
)

// Request types
const (
	TRCReq    = "trc_request"
	TRCPush   = "trc_push"
	ChainReq  = "chain_request"
	ChainPush = "chain_push"
	LatestTRC = "latest_trc_number"
)

// Triggers
const (
	SigVerification = "signature_verification"
	ASInspector     = "trc_inspection"
	App             = "application"
)

// Result types
const (
	Success    = prom.Success
	OkExists   = "ok_exists"
	OkInserted = "ok_inserted"

	ErrMismatch = "err_content_mismatch"
	ErrDB       = prom.ErrDB
	ErrInactive = "err_inactive"
	ErrInternal = prom.ErrInternal
	ErrKey      = "err_key"
	ErrNotFound = "err_not_found"
	ErrParse    = prom.ErrParse
	ErrTransmit = "err_transmit"
	ErrValidate = prom.ErrValidate
	ErrVerify   = prom.ErrVerify
)

var (
	// DB exposes the database metrics.
	DB = newDB()
	// Handler exposes the handler metrics.
	Handler = newHandler()
	// Inserter exposes the inserter metrics.
	Inserter = newInserter()
	// Inspector exposes the inspector metrics.
	Inspector = newInspector()
	// Provider exposes the provider metrics.
	Provider = newProvider()
	// Resolver exposes the resolver metrics.
	Resolver = newResolver()
	// Signer exposes the signer metrics.
	Signer = newSigner()
	// Verifier exposes the verifier metrics.
	Verifier = newVerifier()
)
