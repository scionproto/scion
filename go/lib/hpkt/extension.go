// Copyright 2019 ETH Zurich
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

package hpkt

import (
	"github.com/scionproto/scion/go/lib/common"
)

// ValidateExtensions checks that the sequence of extension in argument extns
// conforms to the SCION protocol specification.
//
// The function returns the sequence of HBH exntensions and the sequence of E2E
// extensions. If an error occurred, both slices are nil, and error is non-nil.
func ValidateExtensions(extns []common.Extension) ([]common.Extension, []common.Extension, error) {
	hbh := []common.Extension{}
	e2e := []common.Extension{}
	seen := make(map[common.ExtnType]struct{}, len(extns))
	haveSCMP := false
	onlyAllowE2E := false

	for i, extn := range extns {
		if extn.Class() == common.End2EndClass {
			onlyAllowE2E = true
		}
		if extn.Class() == common.HopByHopClass && onlyAllowE2E {
			return nil, nil, common.NewBasicError("HBH extension after E2E", nil,
				"offending_type", extn.Type())
		}
		if extn.Type() == common.ExtnSCMPType {
			haveSCMP = true
			if i != 0 {
				return nil, nil, common.NewBasicError("SCMP extension not in 0 position", nil,
					"position", i)
			}
		}
		// FIXME(scrye): Python SCMP error tests require that duplicate
		// extensions be allowed. The tests should be fixed, and parsing should
		// check for duplicates (see
		// https://github.com/scionproto/scion/issues/2421) . Once that is the
		// case, the code below should be uncommented.
		//
		// if _, ok := seen[extn.Type()]; ok {
		//   return nil, nil, common.NewBasicError("duplicate extension", nil, "type", extn.Type())
		// }
		switch extn.Type().Class {
		case common.HopByHopClass:
			hbh = append(hbh, extn)
		case common.End2EndClass:
			e2e = append(e2e, extn)
		default:
			return nil, nil, common.NewBasicError("bad class number, must be E2E or HBH", nil,
				"class", extn.Type().Class)
		}
		seen[extn.Type()] = struct{}{}
	}
	limit := common.ExtnMaxHBH
	if haveSCMP {
		limit += 1
	}
	if len(hbh) > limit {
		return nil, nil, common.NewBasicError("too many HBH extensions", nil,
			"count", len(hbh), "max", limit)
	}
	if len(hbh) == 0 {
		hbh = nil
	}
	if len(e2e) == 0 {
		e2e = nil
	}
	return hbh, e2e, nil
}
