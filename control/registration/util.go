// Copyright 2025 Anapaya Systems
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

package registration

import (
	"strconv"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/prom"
)

type writerLabels struct {
	StartIA addr.IA
	Ingress uint16
	SegType string
	Result  string
}

func (l writerLabels) Expand() []string {
	return []string{
		"start_isd_as", l.StartIA.String(),
		"ingress_interface", strconv.Itoa(int(l.Ingress)),
		"seg_type", l.SegType,
		prom.LabelResult, l.Result,
	}
}

func (l writerLabels) WithResult(result string) writerLabels {
	l.Result = result
	return l
}
