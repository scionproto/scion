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
	"github.com/scionproto/scion/go/lib/ringbuf"
)

const Namespace = "border"

// Result values.
const (
	Success         = prom.Success
	ErrProcess      = prom.ErrProcess
	ErrParse        = prom.ErrParse
	ErrCrypto       = prom.ErrCrypto
	ErrRead         = "err_read"
	ErrWrite        = "err_write"
	ErrValidate     = "err_validate"
	ErrRoute        = "err_route"
	ErrProcessLocal = "err_process_local"
	ErrParsePayload = "err_parse_payload"
)

const Self = "self"

// Metrics initialization.
var (
	Input   = newInput()
	Output  = newOutput()
	Process = newProcess()
	Control = newControl()
)

type IntfLabels struct {
	Intf string
}

func (l *IntfLabels) Labels() []string {
	return []string{"interface"}
}

func (l *IntfLabels) Values() []string {
	return []string{l.Intf}
}

func init() {
	// Initialize ringbuf metrics.
	ringbuf.InitMetrics("border", []string{"ringId"})
}

func IntfToLabel(ifid common.IFIDType) string {
	if ifid == 0 {
		return "loc"
	}
	return fmt.Sprintf("%d", ifid)
}
