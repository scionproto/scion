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

// Package metrics defines and exports router metrics to be scraped by
// prometheus.
package metrics

import (
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/segment/iface"
)

const Namespace = "br"

// Result values.
const (
	Success       = prom.Success
	ErrProcess    = prom.ErrProcess
	ErrParse      = prom.ErrParse
	ErrCrypto     = prom.ErrCrypto
	ErrValidate   = prom.ErrValidate
	ErrInvalidReq = prom.ErrInvalidReq
	// ErrRead is an error reading a packet from snet.
	ErrRead = "err_read"
	// ErrWrite is an error writing a packet to snet.
	ErrWrite = "err_write"
	// ErrRoute is an error routing the packet.
	ErrRoute = "err_route"
	// ErrParsePayload is an error parsing the packet payload.
	ErrParsePayload = "err_parse_payload"
	// ErrResolveSVC is an error resolving a SVC address.
	ErrResolveSVC = "err_resolve_svc"
)

// Metrics initialization.
var (
	Control = newControl()
)

type IntfLabels struct {
	// Intf is the interface ID
	Intf string
	// NeighIA is the remote IA of a given interface.
	NeighIA string
}

// Labels returns the list of labels.
func (l IntfLabels) Labels() []string {
	return []string{"intf", "neigh_ia"}
}

// Values returns the label values in the order defined by Labels.
func (l IntfLabels) Values() []string {
	return []string{l.Intf, l.NeighIA}
}

func IntfToLabel(ifID iface.ID) string {
	if ifID == 0 {
		return "loc"
	}
	return ifID.String()
}
