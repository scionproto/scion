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
	"fmt"
	"strconv"
	"strings"

	"github.com/netsec-ethz/scion/go/lib/common"
)

const (
	IABytes = 4
)

type ISD_AS struct {
	I int
	A int
}

const (
	ErrorIAUnpack = "Unable to unpack ISD-AS"
)

func IAFromRaw(b common.RawBytes) *ISD_AS {
	iaInt := common.Order.Uint32(b)
	return &ISD_AS{I: int(iaInt >> 20), A: int(iaInt & 0x000FFFFF)}
}

func IAFromString(s string) (*ISD_AS, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Invalid ISD-AS %q", s)
	}
	isd, err := strconv.Atoi(parts[0])
	if err != nil {
		e := err.(*strconv.NumError)
		return nil, fmt.Errorf("Unable to parse ISD from %q: %v", s, e.Err)
	}
	as, err := strconv.Atoi(parts[1])
	if err != nil {
		e := err.(*strconv.NumError)
		return nil, fmt.Errorf("Unable to parse AS from %q: %v", s, e.Err)
	}
	return &ISD_AS{I: isd, A: as}, nil
}

func (ia *ISD_AS) Write(b common.RawBytes) {
	common.Order.PutUint32(b, uint32((ia.I<<20)|(ia.A&0x000FFFFF)))
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

func (ia *ISD_AS) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	resIA, err := IAFromString(s)
	if err != nil {
		return err
	}
	ia.I = resIA.I
	ia.A = resIA.A
	return nil
}
