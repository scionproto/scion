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

// Package metrics defines and exports router metrics to be scraped by
// prometheus.
package metrics

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

const Namespace = "border"

// Result values.
const (
	Success    = prom.Success
	ErrProcess = prom.ErrProcess
	ErrParse   = prom.ErrParse
	ErrCrypto  = prom.ErrCrypto
	// ErrRead is an error reading a packet from snet.
	ErrRead = "err_read"
	// ErrWrite is an error writing a packet to snet.
	ErrWrite = "err_write"
	// ErrValidate is an error validating the packet.
	ErrValidate = "err_validate"
	// ErrValidate is an error routing the packet.
	ErrRoute = "err_route"
	// ErrValidate is an error on local processing the packet, ie. SVC resolution.
	ErrProcessLocal = "err_process_local"
	// ErrParsePayload is an error parsing the packet payload.
	ErrParsePayload = "err_parse_payload"
)

// Metrics initialization.
var (
	Input   = newInput()
	Output  = newOutput()
	Process = newProcess()
	Control = newControl()
)

type IntfLabels struct {
	// Itnf in the interface ID
	Intf string
}

// Labels returns the list of labels.
func (l IntfLabels) Labels() []string {
	return []string{"intf"}
}

// Values returns the label values in the order defined by Labels.
func (l IntfLabels) Values() []string {
	return []string{l.Intf}
}

func IntfToLabel(ifid common.IFIDType) string {
	if ifid == 0 {
		return "loc"
	}
	return fmt.Sprintf("%d", ifid)
}
