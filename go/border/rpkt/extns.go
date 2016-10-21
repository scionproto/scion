// Copyright 2016 ETH Zurich
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

package rpkt

import (
	"fmt"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Extension interface {
	fmt.Stringer
	RegisterHooks(*Hooks) *util.Error
}

const ExtMaxHopByHop = 3

const (
	ErrorUnsupportedExt  = "Unsupported extension"
	ErrorExtChainTooLong = "Extension header chain longer than packet"
)

var ExtHBHKnown = map[common.ExtnType]bool{
	common.ExtnTracerouteType: true,
	common.ExtnSCMPType:       true,
	common.ExtnSIBRAType:      true,
}

func (p *Packet) ExtnParse(extType common.ExtnType, start, end int) (Extension, *util.Error) {
	switch {
	case extType == common.ExtnTracerouteType:
		return TracerouteFromRaw(p, start, end)
	case extType == common.ExtnOneHopPathType:
		return OneHopPathFromRaw(p)
	case extType == common.ExtnSCMPType:
		return SCMPExtFromRaw(p, start, end)
	case ExtHBHKnown[extType]:
		return nil, util.NewError("Known but unsupported extension", "type", extType)
	default:
		return nil, util.NewError(ErrorUnsupportedExt, "type", extType)
	}
}
