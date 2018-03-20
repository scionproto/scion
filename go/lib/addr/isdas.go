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

package addr

import (
	"encoding"
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	IABytes = 8
	ISDBits = 16
	ASBits  = 48
	MaxISD  = (1 << ISDBits) - 1
	MaxAS   = (1 << ASBits) - 1
)

type ISD uint16

func ISDFromString(s string) (ISD, error) {
	isd, err := strconv.ParseUint(s, 10, ISDBits)
	if err != nil {
		// err.Error() will contain the original value
		return 0, common.NewBasicError("Unable to parse ISD", err)
	}
	return ISD(isd), nil
}

type AS uint64

func ASFromString(s string) (AS, error) {
	asStr := s
	if strings.Index(s, "_") != -1 {
		// Support AS nubmers that have _ as thousands-separators. E.g. `281474976710655`
		// can also be written as `281_474_976_710_655`.
		parts := strings.Split(s, "_")
		for i := range parts {
			pLen := len(parts[i])
			if i == 0 {
				if pLen == 0 || pLen > 3 {
					// Make sure the first part isn't either 0, or too long
					return 0, common.NewBasicError("Malformed _-separated AS", nil, "val", s)
				}
				continue
			}
			if pLen != 3 {
				// Ensure that there are 3 chars for every part after the first
				return 0, common.NewBasicError("Malformed _-separated AS", nil, "val", s)
			}
		}
		asStr = strings.Join(parts, "")
	}
	as, err := strconv.ParseUint(asStr, 10, ASBits)
	if err != nil {
		// err.Error() will contain the original value
		return 0, common.NewBasicError("Unable to parse AS", err)
	}
	return AS(as), nil
}

func (as AS) String() string {
	decStr := strconv.FormatUint(uint64(as), 10)
	if as > MaxAS {
		return fmt.Sprintf("%s [Illegal AS: larger than %d]", decStr, MaxAS)
	}
	l := len(decStr)
	parts := make([]string, 0, (l/3)+1)
	start := 0
	end := l % 3
	if end == 0 {
		end = 3
	}
	for end <= l {
		parts = append(parts, decStr[start:end])
		start = end
		end += 3
	}
	return strings.Join(parts, "_")
}

var _ fmt.Stringer = IA{}
var _ encoding.TextUnmarshaler = (*IA)(nil)

// IA represents the ISD (Isolation Domain) and AS (Autonomous System) Id of a given SCION AS.
type IA struct {
	I ISD
	A AS
}

func IAFromRaw(b common.RawBytes) IA {
	ia := &IA{}
	ia.Parse(b)
	return *ia
}

func IAFromString(s string) (IA, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return IA{}, common.NewBasicError("Invalid ISD-AS", nil, "val", s)
	}
	isd, err := ISDFromString(parts[0])
	if err != nil {
		return IA{}, err
	}
	as, err := ASFromString(parts[1])
	if err != nil {
		return IA{}, err
	}
	return IA{I: ISD(isd), A: as}, nil
}

func (ia IA) MarshalText() ([]byte, error) {
	return []byte(ia.String()), nil
}

// allows ISD_AS to be used as a map key in JSON.
func (ia *IA) UnmarshalText(text []byte) error {
	newIA, err := IAFromString(string(text))
	if err != nil {
		return err
	}
	*ia = newIA
	return nil
}

func (ia *IA) Parse(b common.RawBytes) {
	*ia = IAInt(common.Order.Uint64(b)).IA()
}

func (ia IA) Write(b common.RawBytes) {
	common.Order.PutUint64(b, uint64(ia.IAInt()))
}

func (ia IA) IAInt() IAInt {
	return IAInt(ia.I)<<ASBits | IAInt(ia.A&MaxAS)
}

func (ia IA) IsZero() bool {
	return ia.I == 0 && ia.A == 0
}

func (ia IA) Eq(other IA) bool {
	return ia.I == other.I && ia.A == other.A
}

func (ia IA) String() string {
	return fmt.Sprintf("%d-%s", ia.I, ia.A)
}

type IAInt uint64

func (iaI IAInt) IA() IA {
	return IA{I: ISD(iaI >> ASBits), A: AS(iaI & MaxAS)}
}
