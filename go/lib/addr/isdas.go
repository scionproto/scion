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
	IABytes   = 8
	ISDBits   = 16
	ASBits    = 48
	BGPASBits = 32
	MaxISD    = (1 << ISDBits) - 1
	MaxAS     = (1 << ASBits) - 1
	MaxBGPAS  = (1 << BGPASBits) - 1

	asPartBits = 16
	asPartBase = 16
	asPartMask = (1 << asPartBits) - 1
	asParts    = ASBits / asPartBits

	ISDFmtPrefix = "ISD"
	ASFmtPrefix  = "AS"
)

// ISD is the ISolation Domain identifier. See formatting and allocations here:
// https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#isd-numbers
type ISD uint16

// ISDFromString parses an ISD from a decimal string.
func ISDFromString(s string) (ISD, error) {
	isd, err := strconv.ParseUint(s, 10, ISDBits)
	if err != nil {
		// err.Error() will contain the original value
		return 0, common.NewBasicError("Unable to parse ISD", err)
	}
	return ISD(isd), nil
}

// ISDFromFileFmt parses an ISD from a file-format string. If prefix is true,
// an 'ISD' prefix is expected and stripped before parsing.
func ISDFromFileFmt(s string, prefix bool) (ISD, error) {
	if prefix {
		if !strings.HasPrefix(s, ISDFmtPrefix) {
			return 0, common.NewBasicError(
				fmt.Sprintf("'%s' prefix missing", ISDFmtPrefix), nil, "raw", s)
		}
		s = s[len(ISDFmtPrefix):]
	}
	return ISDFromString(s)
}

// AS is the Autonomous System idenifier. See formatting and allocations here:
// https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#as-numbers
type AS uint64

// ASFromString parses an AS from a decimal (in the case of the 32bit BGP AS
// number space) or ipv6-style hex (in the case of SCION-only AS numbers)
// string.
func ASFromString(s string) (AS, error) {
	return asParse(s, ":")
}

// ASFromFileFmt parses an AS from a file-format string. This is the same
// format as ASFromString expects, with ':' replaced by '_'. If prefix is true,
// an 'AS' prefix is expected and stripped before parsing.
func ASFromFileFmt(s string, prefix bool) (AS, error) {
	if prefix {
		if !strings.HasPrefix(s, ASFmtPrefix) {
			return 0, common.NewBasicError(
				fmt.Sprintf("'%s' prefix missing", ASFmtPrefix), nil, "raw", s)
		}
		s = s[len(ASFmtPrefix):]
	}
	return asParse(s, "_")
}

func asParse(s string, sep string) (AS, error) {
	if strings.Index(s, sep) == -1 {
		// Must be a BGP AS, parse as 32-bit decimal number
		as, err := strconv.ParseUint(s, 10, BGPASBits)
		if err != nil {
			// err.Error() will contain the original value
			return 0, common.NewBasicError("Unable to parse AS", err)
		}
		return AS(as), nil
	}
	parts := strings.Split(s, sep)
	if len(parts) != asParts {
		return 0, common.NewBasicError(
			fmt.Sprintf("Unable to parse AS: wrong number of %s separators", sep), nil,
			"expected", asParts, "actual", len(parts), "raw", s)
	}
	var as AS
	for i := 0; i < asParts; i++ {
		as <<= asPartBits
		v, err := strconv.ParseUint(parts[i], asPartBase, asPartBits)
		if err != nil {
			return 0, common.NewBasicError("Unable to parse AS part", err, "raw", s)
		}
		as |= AS(v)
	}
	return as, nil
}

func (as AS) String() string {
	return as.fmt(':')
}

// FileFmt formats an AS for use in a file name, using '_' instead of ':' as
// the separator for SCION-only AS numbers.
func (as AS) FileFmt() string {
	return as.fmt('_')
}

func (as AS) fmt(sep byte) string {
	if as > MaxAS {
		return fmt.Sprintf("%d [Illegal AS: larger than %d]", as, AS(MaxAS))
	}
	// Format BGP ASes as decimal
	if as <= MaxBGPAS {
		return strconv.FormatUint(uint64(as), 10)
	}
	// Format all other ASes as 'sep'-separated hex.
	const maxLen = len("ffff:ffff:ffff")
	b := make([]byte, 0, maxLen)
	for i := 0; i < asParts; i++ {
		if i > 0 {
			b = append(b, sep)
		}
		shift := uint(asPartBits * (asParts - i - 1))
		s := strconv.FormatUint(uint64(as>>shift)&asPartMask, asPartBase)
		b = append(b, s...)
	}
	return string(b)
}

var _ fmt.Stringer = IA{}
var _ encoding.TextUnmarshaler = (*IA)(nil)

// IA represents the ISD (ISolation Domain) and AS (Autonomous System) Id of a given SCION AS.
type IA struct {
	I ISD
	A AS
}

func IAFromRaw(b common.RawBytes) IA {
	ia := &IA{}
	ia.Parse(b)
	return *ia
}

/// IAFromString parses an IA from a string of the format 'ia-as'.
func IAFromString(s string) (IA, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return IA{}, common.NewBasicError("Invalid ISD-AS", nil, "raw", s)
	}
	isd, err := ISDFromString(parts[0])
	if err != nil {
		return IA{}, err
	}
	as, err := ASFromString(parts[1])
	if err != nil {
		return IA{}, err
	}
	return IA{I: isd, A: as}, nil
}

// IAFromFileFmt parses an IA from a file-format
func IAFromFileFmt(s string, prefixes bool) (IA, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return IA{}, common.NewBasicError("Invalid ISD-AS", nil, "raw", s)
	}
	isd, err := ISDFromFileFmt(parts[0], prefixes)
	if err != nil {
		return IA{}, err
	}
	as, err := ASFromFileFmt(parts[1], prefixes)
	if err != nil {
		return IA{}, err
	}
	return IA{I: isd, A: as}, nil
}

func (ia IA) MarshalText() ([]byte, error) {
	return []byte(ia.String()), nil
}

// allows IA to be used as a map key in JSON.
func (ia *IA) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*ia = IA{}
		return nil
	}
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

func (ia IA) FileFmt(prefixes bool) string {
	fmts := "%d-%s"
	if prefixes {
		fmts = "ISD%d-AS%s"
	}
	return fmt.Sprintf(fmts, ia.I, ia.A.FileFmt())
}

// IAInt is an integer representation of an ISD-AS.
type IAInt uint64

func (iaI IAInt) IA() IA {
	return IA{I: ISD(iaI >> ASBits), A: AS(iaI & MaxAS)}
}
