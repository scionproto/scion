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

package addr

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/serrors"
)

// ParseFormattedIA parses an IA that was formatted with the FormatIA function.
// The same options must be provided to successfully parse.
func ParseFormattedIA(ia string, opts ...FormatOption) (IA, error) {
	parts := strings.Split(ia, "-")
	if len(parts) != 2 {
		return 0, serrors.New("invalid ISD-AS", "value", ia)
	}
	isd, err := ParseFormattedISD(parts[0], opts...)
	if err != nil {
		return 0, serrors.WrapStr("parsing ISD part", err, "value", ia)
	}
	as, err := ParseFormattedAS(parts[1], opts...)
	if err != nil {
		return 0, serrors.WrapStr("parsing AS part", err, "value", ia)
	}
	return MustIAFrom(isd, as), nil
}

// ParseFormattedISD parses an ISD number that was formatted with the FormatISD
// function. The same options must be provided to successfully parse.
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
func ParseFormattedAS(as string, opts ...FormatOption) (AS, error) {
	o := applyFormatOptions(opts)
	if o.defaultPrefix {
		trimmed := strings.TrimPrefix(as, "AS")
		if trimmed == as {
			return 0, serrors.New("prefix is missing", "prefix", "AS", "value", as)
		}
		as = trimmed
	}
	return parseAS(as, o.separator)
}

// FormatIA formats the ISD-AS.
func FormatIA(ia IA, opts ...FormatOption) string {
	o := applyFormatOptions(opts)
	as := fmtAS(ia.AS(), o.separator)
	if o.defaultPrefix {
		return fmt.Sprintf("ISD%d-AS%s", ia.ISD(), as)
	}
	return fmt.Sprintf("%d-%s", ia.ISD(), as)
}

// FormatISD formats the ISD number.
func FormatISD(isd ISD, opts ...FormatOption) string {
	o := applyFormatOptions(opts)
	if o.defaultPrefix {
		return fmt.Sprintf("ISD%d", isd)
	}
	return strconv.Itoa(int(isd))
}

// FormatAS formats the AS number.
func FormatAS(as AS, opts ...FormatOption) string {
	o := applyFormatOptions(opts)
	s := fmtAS(as, o.separator)
	if o.defaultPrefix {
		return "AS" + s
	}
	return s
}

func fmtAS(as AS, sep string) string {
	if !as.inRange() {
		return fmt.Sprintf("%d [Illegal AS: larger than %d]", as, MaxAS)
	}
	// Format BGP ASes as decimal
	if as <= MaxBGPAS {
		return strconv.FormatUint(uint64(as), 10)
	}
	// Format all other ASes as 'sep'-separated hex.
	const maxLen = len("ffff:ffff:ffff")
	var b strings.Builder
	b.Grow(maxLen)
	for i := 0; i < asParts; i++ {
		if i > 0 {
			b.WriteString(sep)
		}
		shift := uint(asPartBits * (asParts - i - 1))
		b.WriteString(strconv.FormatUint(uint64(as>>shift)&asPartMask, asPartBase))
	}
	return b.String()
}

type FormatOption func(*formatOptions)

type formatOptions struct {
	defaultPrefix bool
	separator     string
}

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
func WithDefaultPrefix() FormatOption {
	return func(o *formatOptions) {
		o.defaultPrefix = true
	}
}

// WithSeparator sets the separator to use for formatting AS numbers. In case of
// the empty string, the ':' is used.
func WithSeparator(separator string) FormatOption {
	return func(o *formatOptions) {
		o.separator = separator
	}
}

// WithFileSeparator returns an option that sets the separator to underscore.
func WithFileSeparator() FormatOption {
	return WithSeparator("_")
}
