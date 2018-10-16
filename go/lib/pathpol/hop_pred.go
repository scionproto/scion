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

// A HopPredicate specifies a hop in the ACL or Sequence of the path policy,
// see docs/PathPolicy.md.
type HopPredicate struct {
	ISD   addr.ISD
	AS    addr.AS
	IfIDs []common.IFIDType
}

func NewHopPredicate() *HopPredicate {
	return &HopPredicate{IfIDs: make([]common.IFIDType, 1)}
}

func HopPredicateFromString(str string) (HopPredicate, error) {
	var err error
	var ifIDs = make([]common.IFIDType, 1)
	// Parse ISD
	dashParts := strings.Split(str, "-")
	isd, err := addr.ISDFromString(dashParts[0])
	if err != nil {
		return HopPredicate{},
			common.NewBasicError("Failed to parse ISD", err, "value", str)
	}
	if len(dashParts) == 1 {
		return HopPredicate{ISD: isd, IfIDs: ifIDs}, nil
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
		return HopPredicate{ISD: isd, AS: as, IfIDs: ifIDs}, nil
	}
	if len(hashParts) != 2 {
		return HopPredicate{},
			common.NewBasicError("Failed to parse hop predicate, multiple hashes found", nil,
				"value", str)
	}
	// Parse IfIDs if present
	commaParts := strings.Split(hashParts[1], ",")
	if ifIDs[0], err = parseIfID(commaParts[0]); err != nil {
		return HopPredicate{}, common.NewBasicError("Failed to parse ifids", err, "value", str)
	}
	if len(commaParts) == 2 {
		if as == 0 {
			return HopPredicate{}, common.NewBasicError(
				"Failed to parse hop predicate, there must be a single wildcard IF",
				nil, "value", str)
		}
		ifID, err := parseIfID(commaParts[1])
		if err != nil {
			return HopPredicate{}, common.NewBasicError("Failed to parse ifids", err, "value", str)
		}
		ifIDs = append(ifIDs, ifID)
	}
	if len(commaParts) > 2 {
		return HopPredicate{},
			common.NewBasicError("Failed to parse hop predicate, too many interfaces found", nil,
				"value", str)
	}
	// IfID cannot be set when the AS is a wildcard
	if ifIDs[0] != 0 && as == 0 {
		return HopPredicate{},
			common.NewBasicError("Failed to parse hop predicate, IfIDs must be 0",
				nil, "value", str)
	}
	return HopPredicate{ISD: isd, AS: as, IfIDs: ifIDs}, nil
}

func (hp HopPredicate) String() string {
	ifids := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(hp.IfIDs)), ","), "[]")
	return fmt.Sprintf("%s#%s", addr.IA{I: hp.ISD, A: hp.AS}, ifids)
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
	nhp, err := HopPredicateFromString(str)
	if err != nil {
		return err
	}
	hp.ISD = nhp.ISD
	hp.AS = nhp.AS
	hp.IfIDs = nhp.IfIDs
	return nil
}

func parseIfID(str string) (common.IFIDType, error) {
	ifid, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, err
	}
	return common.IFIDType(ifid), nil
}

// pathIFMatchHopPred takes a PathInterface, a HopPredicate and a bool indicating if the ingress
// interface needs to be matching. It returns true if the HopPredicate matches the PathInterface
func pathIFMatchHopPred(pi sciond.PathInterface, hp HopPredicate, in bool) bool {
	piIA := pi.ISD_AS()
	if hp.ISD != 0 && piIA.I != hp.ISD {
		return false
	}
	if hp.AS != 0 && piIA.A != hp.AS {
		return false
	}
	ifInd := 0
	// the IF index is set to 1 if
	// - there are two IFIDs and
	// - the ingress interface should not be matched
	if len(hp.IfIDs) == 2 && !in {
		ifInd = 1
	}
	if hp.IfIDs[ifInd] != 0 && hp.IfIDs[ifInd] != pi.IfID {
		return false
	}
	return true
}
