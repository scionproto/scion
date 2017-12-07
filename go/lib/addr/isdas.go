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
	IABytes = 4
	MaxISD  = (1 << 12) - 1
	MaxAS   = (1 << 20) - 1
)

var _ encoding.TextUnmarshaler = (*ISD_AS)(nil)

type ISD_AS struct {
	I int
	A int
}

const (
	ErrorIAUnpack = "Unable to unpack ISD-AS"
)

func IAFromRaw(b common.RawBytes) *ISD_AS {
	ia := &ISD_AS{}
	ia.Parse(b)
	return ia
}

func IAFromString(s string) (*ISD_AS, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil, common.NewCError("Invalid ISD-AS", "val", s)
	}
	isd, err := strconv.Atoi(parts[0])
	if err != nil {
		e := err.(*strconv.NumError)
		return nil, common.NewCError("Unable to parse ISD", "val", s, "err", e.Err)
	}
	if isd > MaxISD {
		return nil, common.NewCError("Invalid ISD-AS: ISD too large",
			"max", MaxISD, "actual", isd, "raw", s)
	}
	as, err := strconv.Atoi(parts[1])
	if err != nil {
		e := err.(*strconv.NumError)
		return nil, common.NewCError("Unable to parse AS", "val", s, "err", e.Err)
	}
	if as > MaxAS {
		return nil, common.NewCError("Invalid ISD-AS: AS too large",
			"max", MaxAS, "actual", as, "raw", s)
	}
	return &ISD_AS{I: isd, A: as}, nil
}

func (ia ISD_AS) MarshalText() ([]byte, error) {
	return []byte(ia.String()), nil
}

// allows ISD_AS to be used as a map key in JSON.
func (ia *ISD_AS) UnmarshalText(text []byte) error {
	newIA, err := IAFromString(string(text))
	if err != nil {
		return err
	}
	*ia = *newIA
	return nil
}

func (ia *ISD_AS) Parse(b common.RawBytes) {
	newIA := IAInt(common.Order.Uint32(b)).IA()
	*ia = *newIA
}

func (ia *ISD_AS) Write(b common.RawBytes) {
	common.Order.PutUint32(b, uint32(ia.IAInt()))
}

func (ia *ISD_AS) IAInt() IAInt {
	return IAInt((ia.I << 20) | (ia.A & 0x000FFFFF))
}

func (ia *ISD_AS) SizeOf() int {
	return IABytes
}

func (ia *ISD_AS) Copy() *ISD_AS {
	return &ISD_AS{I: ia.I, A: ia.A}
}

func (ia *ISD_AS) Eq(other *ISD_AS) bool {
	return ia.I == other.I && ia.A == other.A
}

func (ia ISD_AS) String() string {
	return fmt.Sprintf("%d-%d", ia.I, ia.A)
}

type IAInt uint32

func (iaI IAInt) IA() *ISD_AS {
	return &ISD_AS{I: int(iaI >> 20), A: int(iaI & 0x000FFFFF)}
}
