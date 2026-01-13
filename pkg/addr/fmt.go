// Copyright 2022 Anapaya Systems
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
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// ParseFormattedIA parses an IA that was formatted with the FormatIA function.
// The same options must be provided to successfully parse.
// @ trusted
// @ requires false
func ParseFormattedIA(ia string, opts ...FormatOption) (IA, error) {
	parts := strings.Split(ia, "-")
	if len(parts) != 2 {
		return 0, serrors.New("invalid ISD-AS", "value", ia)
	}
	isd, err := ParseFormattedISD(parts[0], opts...)
	if err != nil {
		return 0, serrors.Wrap("parsing ISD part", err, "value", ia)
	}
	a, err := ParseFormattedAS(parts[1], opts...)
	if err != nil {
		return 0, serrors.Wrap("parsing AS part", err, "value", ia)
	}
	return MustIAFrom(isd, a), nil
}

// ParseFormattedISD parses an ISD number that was formatted with the FormatISD
// function. The same options must be provided to successfully parse.
// @ trusted
// @ requires false
func ParseFormattedISD(isd string, opts ...FormatOption) (ISD, error) {
	o := applyFormatOptions(opts)
	if o.defaultPrefix {
		trimmed := strings.TrimPrefix(isd, "ISD")
		if trimmed == isd {
			return 0, serrors.New("prefix is missing", "prefix", "ISD", "value", isd)
		}
		isd = trimmed
	}
	return ParseISD(isd)
}

// ParseFormattedAS parses an AS number that was formatted with the FormatAS
// function. The same options must be provided to successfully parse.
// @ trusted
// @ requires false
func ParseFormattedAS(a string, opts ...FormatOption) (AS, error) {
	o := applyFormatOptions(opts)
	if o.defaultPrefix {
		trimmed := strings.TrimPrefix(a, "AS")
		if trimmed == a {
			return 0, serrors.New("prefix is missing", "prefix", "AS", "value", a)
		}
		a = trimmed
	}
	return parseAS(a, o.separator)
}

// FormatIA formats the ISD-AS.
// @ trusted
// @ requires false
func FormatIA(ia IA, opts ...FormatOption) string {
	o := applyFormatOptions(opts)
	a := fmtAS(ia.AS(), o.separator)
	if o.defaultPrefix {
		return fmt.Sprintf("ISD%d-AS%s", ia.ISD(), a)
	}
	return fmt.Sprintf("%d-%s", ia.ISD(), a)
}

// FormatISD formats the ISD number.
// @ trusted
// @ requires false
func FormatISD(isd ISD, opts ...FormatOption) string {
	o := applyFormatOptions(opts)
	if o.defaultPrefix {
		return fmt.Sprintf("ISD%d", isd)
	}
	return strconv.Itoa(int(isd))
}

// FormatAS formats the AS number.
// @ trusted
// @ requires false
func FormatAS(a AS, opts ...FormatOption) string {
	o := applyFormatOptions(opts)
	s := fmtAS(a, o.separator)
	if o.defaultPrefix {
		return "AS" + s
	}
	return s
}

// @ decreases
func fmtAS(a AS, sep string) string {
	if !a.inRange() {
		return fmt.Sprintf("%d [Illegal AS: larger than %d]", a, MaxAS)
	}
	// Format BGP ASes as decimal
	if a <= MaxBGPAS {
		return strconv.FormatUint(uint64(a), 10)
	}
	// Format all other ASes as 'sep'-separated hex.
	var maxLen = len("ffff:ffff:ffff")
	var b /*@@@*/ strings.Builder
	// @ b.ZeroBuilderIsReadyToUse()
	b.Grow(maxLen)
	// @ invariant b.Mem()
	// @ decreases asParts - i
	for i := 0; i < asParts; i++ {
		if i > 0 {
			b.WriteString(sep)
		}
		shift := uint(asPartBits * (asParts - i - 1))
		b.WriteString(strconv.FormatUint(uint64(a>>shift)&asPartMask, asPartBase))
	}
	return b.String()
}

// The following is a type alias instead of a declared type. Currently, Gobra does
// not support this type declaration.
type FormatOption = func(*formatOptions)

type formatOptions struct {
	defaultPrefix bool
	separator     string
}

// @ trusted
// @ requires false
func applyFormatOptions(opts []FormatOption) formatOptions {
	o := formatOptions{
		defaultPrefix: false,
		separator:     ":",
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// WithDefaultPrefix enables the default prefix which depends on the type. For
// the AS number, the prefix is 'AS'. For the ISD number, the prefix is 'ISD'.
// @ trusted
// @ requires false
func WithDefaultPrefix() FormatOption {
	return func(o *formatOptions) {
		o.defaultPrefix = true
	}
}

// WithSeparator sets the separator to use for formatting AS numbers. In case of
// the empty string, the ':' is used.
// @ trusted
// @ requires false
func WithSeparator(separator string) FormatOption {
	return func(o *formatOptions) {
		o.separator = separator
	}
}

// WithFileSeparator returns an option that sets the separator to underscore.
// @ trusted
// @ requires false
func WithFileSeparator() FormatOption {
	return WithSeparator("_")
}
