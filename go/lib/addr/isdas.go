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
type AS uint64

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
	isd, err := strconv.ParseUint(parts[0], 10, ISDBits)
	if err != nil {
		// err.Error() will contain the original value
		return IA{}, common.NewBasicError("Unable to parse ISD", err)
	}
	as, err := strconv.ParseUint(parts[1], 10, ASBits)
	if err != nil {
		// err.Error() will contain the original value
		return IA{}, common.NewBasicError("Unable to parse AS", err)
	}
	return IA{I: ISD(isd), A: AS(as)}, nil
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
	return fmt.Sprintf("%d-%d", ia.I, ia.A)
}

type IAInt uint64

func (iaI IAInt) IA() IA {
	return IA{I: ISD(iaI >> ASBits), A: AS(iaI & MaxAS)}
}
