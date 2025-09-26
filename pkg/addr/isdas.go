// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// +gobra

package addr

import (
	"encoding"
	"flag"
	"fmt"
	"strconv"
	"strings"

	// @ "github.com/scionproto/scion/gobra/utils"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	IABytes       = 8
	ISDBits       = 16
	ASBits        = 48
	BGPASBits     = 32
	MaxISD    ISD = (1 << ISDBits) - 1
	MaxAS     AS  = (1 << ASBits) - 1
	MaxBGPAS  AS  = (1 << BGPASBits) - 1

	asPartBits = 16
	asPartBase = 16
	asPartMask = (1 << asPartBits) - 1
	asParts    = ASBits / asPartBits
)

// ISD is the ISolation Domain identifier. See formatting and allocations here:
// https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#isd-numbers
type ISD uint16

// ParseISD parses an ISD from a decimal string. Note that ISD 0 is parsed
// without any errors.
// @ ensures err != nil ==> err.ErrorMem()
// @ decreases
func ParseISD(s string) (res ISD, err error) {
	isd, err := strconv.ParseUint(s, 10, ISDBits)
	if err != nil {
		return 0, serrors.Wrap("parsing ISD", err)
	}
	return ISD(isd), nil
}

// MustParseISD parses s and returns the corresponding addr.ISD object. It panics
// if s is not valid ISD representation.
// @ trusted
// @ requires false
func MustParseISD(s string) ISD {
	isd, err := ParseISD(s)
	if err != nil {
		panic(err)
	}
	return isd
}

// @ decreases
func (isd ISD) String() string {
	return strconv.FormatUint(uint64(isd), 10)
}

var _ encoding.TextUnmarshaler = (*AS)(nil)

// AS is the Autonomous System identifier. See formatting and allocations here:
// https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#as-numbers
type AS uint64

// ParseAS parses an AS from a decimal (in the case of the 32bit BGP AS number
// space) or ipv6-style hex (in the case of SCION-only AS numbers) string.
// @ ensures err == nil ==> res.InRangeSpec()
// @ ensures err != nil ==> err.ErrorMem()
// @ decreases
func ParseAS(a string) (res AS, err error) {
	return parseAS(a, ":")
}

// MustParseAS parses s and returns the corresponding addr.AS object. It panics
// if s is not valid AS representation.
// @ trusted
// @ requires false
func MustParseAS(s string) AS {
	a, err := ParseAS(s)
	if err != nil {
		panic(err)
	}
	return a
}

// @ ensures err == nil ==> res.InRangeSpec()
// @ ensures err != nil ==> err.ErrorMem()
// @ decreases
func parseAS(a string, sep string) (res AS, err error) {
	parts := strings.Split(a, sep)
	if len(parts) == 1 {
		// Must be a BGP AS, parse as 32-bit decimal number
		return asParseBGP(a)
	}

	if len(parts) != asParts {
		return 0, serrors.New("wrong number of separators", "sep", sep, "value", a)
	}
	var parsed AS
	//@ invariant 0 <= i && i <= asParts
	//@ invariant acc(parts)
	//@ decreases asParts - i
	for i := 0; i < asParts; i++ {
		parsed <<= asPartBits
		v, err := strconv.ParseUint(parts[i], asPartBase, asPartBits)
		if err != nil {
			return 0, serrors.Wrap("parsing AS part", err, "index", i, "value", a)
		}
		parsed |= AS(v)
	}
	// This should not be reachable. However, we leave it here to protect
	// against future refactor mistakes.
	if !parsed.inRange() {
		return 0, serrors.New("AS out of range", "max", MaxAS, "value", a)
	}
	return parsed, nil
}

// @ ensures err == nil ==> res.InRangeSpec()
// @ ensures err != nil ==> err.ErrorMem()
// @ decreases
func asParseBGP(s string) (res AS, err error) {
	a, err := strconv.ParseUint(s, 10, BGPASBits)
	if err != nil {
		return 0, serrors.Wrap("parsing BGP AS", err)
	}
	// The following annotation is needed to prove res.InRangeSpec().
	// Gobra is not able to establish the upper limit of a without this
	// annotation.
	// @ strconv.Exp2to32()
	return AS(a), nil
}

// @ decreases
func (a AS) String() string {
	return fmtAS(a, ":")
}

// @ ensures res == a.InRangeSpec()
// @ decreases
func (a AS) inRange() (res bool) {
	return a <= MaxAS
}

// @ ensures err == nil ==> acc(res)
// @ ensures err != nil ==> err.ErrorMem()
// @ decreases
func (a AS) MarshalText() (res []byte, err error) {
	if !a.inRange() {
		return nil, serrors.New("AS out of range", "max", MaxAS, "value", a)
	}
	return []byte(a.String()), nil
}

// @ preserves a.Mem()
// @ preserves acc(text, utils.ReadPerm)
// @ ensures   err != nil ==> err.ErrorMem()
// @ decreases
func (a *AS) UnmarshalText(text []byte) (err error) {
	parsed, err := ParseAS(string(text))
	if err != nil {
		return err
	}
	// @ unfold a.Mem()
	*a = parsed
	// @ fold a.Mem()
	return nil
}

var (
	_ fmt.Stringer             = IA(0)
	_ encoding.TextUnmarshaler = (*IA)(nil)
	_ flag.Value               = (*IA)(nil)
)

// IA represents the ISD (ISolation Domain) and AS (Autonomous System) Id of a given SCION AS.
// The highest 16 bit form the ISD number and the lower 48 bits form the AS number.
type IA uint64

// MustIAFrom creates an IA from the ISD and AS number. It panics if any error
// is encountered. Callers must ensure that the values passed to this function
// are valid.
// @ requires a.InRangeSpec()
// @ decreases
func MustIAFrom(isd ISD, a AS) IA {
	ia, err := IAFrom(isd, a)
	if err != nil {
		panic(fmt.Sprintf("parsing ISD-AS: %v", err))
	}
	return ia
}

// IAFrom creates an IA from the ISD and AS number.
// @ ensures a.InRangeSpec() == (err == nil)
// @ ensures err != nil ==> err.ErrorMem()
// @ decreases
func IAFrom(isd ISD, a AS) (ret IA, err error) {
	if !a.inRange() {
		return 0, serrors.New("AS out of range", "max", MaxAS, "value", a)
	}
	return IA(isd)<<ASBits | IA(a&MaxAS), nil
}

// ParseIA parses an IA from a string of the format 'isd-as'.
// @ ensures err != nil ==> err.ErrorMem()
// @ decreases
func ParseIA(ia string) (res IA, err error) {
	parts := strings.Split(ia, "-")
	if len(parts) != 2 {
		return 0, serrors.New("invalid ISD-AS", "value", ia)
	}
	isd, err := ParseISD(parts[0])
	if err != nil {
		return 0, err
	}
	a, err := ParseAS(parts[1])
	if err != nil {
		return 0, err
	}
	return MustIAFrom(isd, a), nil
}

// MustParseIA parses s and returns the corresponding addr.IA object. It
// panics if s is not a valid ISD-AS representation.
// @ trusted
// @ requires false
func MustParseIA(s string) IA {
	ia, err := ParseIA(s)
	if err != nil {
		panic(err)
	}
	return ia
}

// @ decreases
func (ia IA) ISD() ISD {
	return ISD(ia >> ASBits)
}

// @ decreases
func (ia IA) AS() AS {
	return AS(ia) & MaxAS
}

// @ ensures acc(s)
// @ ensures err == nil
// @ decreases
func (ia IA) MarshalText() (s []byte, err error) {
	return []byte(ia.String()), nil
}

// @ preserves ia.Mem()
// @ preserves acc(b, utils.ReadPerm)
// @ decreases
func (ia *IA) UnmarshalText(b []byte) error {
	parsed, err := ParseIA(string(b))
	if err != nil {
		return err
	}
	// @ unfold ia.Mem()
	*ia = parsed
	// @ fold ia.Mem()
	return nil
}

func (ia IA) IsZero() bool {
	return ia == 0
}

func (ia IA) Equal(other IA) bool {
	return ia == other
}

// IsWildcard returns whether the ia has a wildcard part (isd or as).
func (ia IA) IsWildcard() bool {
	return ia.ISD() == 0 || ia.AS() == 0
}

// @ decreases
func (ia IA) String() string {
	return fmt.Sprintf("%d-%s", ia.ISD(), ia.AS())
}

// Set implements flag.Value interface
// @ preserves ia.Mem()
// @ ensures   err != nil ==> err.ErrorMem()
// @ decreases
func (ia *IA) Set(s string) (err error) {
	pIA, err := ParseIA(s)
	if err != nil {
		return err
	}
	// @ unfold ia.Mem()
	*ia = pIA
	// @ fold ia.Mem()
	return nil
}
