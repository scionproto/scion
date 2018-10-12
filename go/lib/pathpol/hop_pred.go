// Copyright 2018 ETH Zurich
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

package pathpol

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
)

type HopPredicate struct {
	ISD  addr.ISD
	AS   addr.AS
	IfID common.IFIDType
}

func NewHopPredicate(str string) (HopPredicate, error) {
	var err error
	// Parse ISD
	dashParts := strings.Split(str, "-")
	isd, err := addr.ISDFromString(dashParts[0])
	if err != nil {
		return HopPredicate{},
			common.NewBasicError("Failed to parse ISD", err, "value", str)
	}
	if len(dashParts) == 1 {
		return HopPredicate{ISD: isd}, nil
	}
	if len(dashParts) != 2 {
		return HopPredicate{},
			common.NewBasicError("Failed to parse hop predicate, multiple dashes found", nil,
				"value", str)
	}
	// Parse AS if present
	hashParts := strings.Split(dashParts[1], "#")
	as, err := addr.ASFromString(hashParts[0])
	if err != nil {
		return HopPredicate{}, common.NewBasicError("Failed to parse AS", err, "value", str)
	}
	if len(hashParts) == 1 {
		return HopPredicate{ISD: isd, AS: as}, nil
	}
	if len(hashParts) != 2 {
		return HopPredicate{},
			common.NewBasicError("Failed to parse hop predicate, multiple hashes found", nil,
				"value", str)
	}
	// Parse IfID if present
	ifid, err := strconv.ParseUint(hashParts[1], 10, 64)
	if err != nil {
		return HopPredicate{}, common.NewBasicError("Failed to parse ifid", err, "value", str)
	}
	// IfID cannot be set when the AS is a wildcard
	if ifid != 0 && as == 0 {
		return HopPredicate{},
			common.NewBasicError("Failed to parse hop predicate, IfID must be 0",
				nil, "value", str)
	}
	return HopPredicate{ISD: isd, AS: as, IfID: common.IFIDType(ifid)}, nil
}

func (hp HopPredicate) String() string {
	return fmt.Sprintf("%s#%d", addr.IA{I: hp.ISD, A: hp.AS}, hp.IfID)
}

func (hp *HopPredicate) MarshalJSON() ([]byte, error) {
	return json.Marshal(hp.String())
}

func (hp *HopPredicate) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}
	nhp, err := NewHopPredicate(str)
	if err != nil {
		return err
	}
	hp.ISD = nhp.ISD
	hp.AS = nhp.AS
	hp.IfID = nhp.IfID
	return nil
}

func pathIFMatchHopPred(x sciond.PathInterface, y HopPredicate) bool {
	xIA := x.ISD_AS()
	if xIA.I != 0 && y.ISD != 0 && xIA.I != y.ISD {
		return false
	}
	if xIA.A != 0 && y.AS != 0 && xIA.A != y.AS {
		return false
	}
	if x.IfID != 0 && y.IfID != 0 && x.IfID != y.IfID {
		return false
	}
	return true
}
