// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
)

// A HopPredicate specifies a hop in the ACL or Sequence of the path policy,
// see docs/PathPolicy.md.
type HopPredicate struct {
	ISD   addr.ISD
	AS    addr.AS
	IfIDs []iface.ID
}

func NewHopPredicate() *HopPredicate {
	return &HopPredicate{IfIDs: make([]iface.ID, 1)}
}

func HopPredicateFromString(str string) (*HopPredicate, error) {
	var err error
	if err = validateHopPredStr(str); err != nil {
		return &HopPredicate{}, err
	}
	var ifIDs = make([]iface.ID, 1)
	// Parse ISD
	dashParts := strings.Split(str, "-")
	isd, err := addr.ParseISD(dashParts[0])
	if err != nil {
		return &HopPredicate{}, serrors.Wrap("Failed to parse ISD", err, "value", str)
	}
	if len(dashParts) == 1 {
		return &HopPredicate{ISD: isd, IfIDs: ifIDs}, nil
	}
	// Parse AS if present
	hashParts := strings.Split(dashParts[1], "#")
	as, err := addr.ParseAS(hashParts[0])
	if err != nil {
		return &HopPredicate{}, serrors.Wrap("Failed to parse AS", err, "value", str)
	}
	if len(hashParts) == 1 {
		return &HopPredicate{ISD: isd, AS: as, IfIDs: ifIDs}, nil
	}
	// Parse IfIDs if present
	commaParts := strings.Split(hashParts[1], ",")
	if ifIDs[0], err = parseIfID(commaParts[0]); err != nil {
		return &HopPredicate{}, serrors.Wrap("Failed to parse ifIDs", err, "value", str)
	}
	if len(commaParts) == 2 {
		ifID, err := parseIfID(commaParts[1])
		if err != nil {
			return &HopPredicate{}, serrors.Wrap("Failed to parse ifIDs", err, "value", str)
		}
		ifIDs = append(ifIDs, ifID)
	}
	// IfID cannot be set when the AS is a wildcard
	if as == 0 && (ifIDs[0] != 0 || (len(ifIDs) > 1 && ifIDs[1] != 0)) {
		return &HopPredicate{}, serrors.New("Failed to parse hop predicate, IfIDs must be 0",
			"value", str)
	}
	return &HopPredicate{ISD: isd, AS: as, IfIDs: ifIDs}, nil
}

// pathIFMatch takes a PathInterface and a bool indicating if the ingress
// interface needs to be matching. It returns true if the HopPredicate matches the PathInterface
func (hp *HopPredicate) pathIFMatch(pi snet.PathInterface, in bool) bool {
	if hp.ISD != 0 && pi.IA.ISD() != hp.ISD {
		return false
	}
	if hp.AS != 0 && pi.IA.AS() != hp.AS {
		return false
	}
	ifInd := 0
	// the IF index is set to 1 if
	// - there are two IFIDs and
	// - the ingress interface should not be matched
	if len(hp.IfIDs) == 2 && !in {
		ifInd = 1
	}
	if hp.IfIDs[ifInd] != 0 && hp.IfIDs[ifInd] != pi.ID {
		return false
	}
	return true
}

func (hp *HopPredicate) matchesAll() bool {
	if hp == nil {
		return true
	}
	// hp.AS == 0 implies that there is exactly one 0 interface.
	return hp.ISD == 0 && hp.AS == 0
}

func (hp HopPredicate) String() string {
	var s []string
	for _, ifID := range hp.IfIDs {
		s = append(s, ifID.String())
	}
	return fmt.Sprintf("%d-%s#%s", hp.ISD, hp.AS, strings.Join(s, ","))
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
	*hp = *nhp
	return err
}

func parseIfID(str string) (iface.ID, error) {
	ifID, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, err
	}
	return iface.ID(ifID), nil
}

// validateHopPredStr checks if str has the correct amount of delimiters
func validateHopPredStr(str string) error {
	dashes := strings.Count(str, "-")
	hashes := strings.Count(str, "#")
	commas := strings.Count(str, ",")
	if dashes > 1 || hashes > 1 || commas > 1 {
		return serrors.New("Failed to parse hop predicate, found delimiter too often",
			"dashes", dashes, "hashes", hashes, "commas", commas)
	}
	if dashes == 0 && (hashes > 0 || commas > 0) {
		return serrors.New("Can't specify IFIDs without AS")
	}
	return nil
}
