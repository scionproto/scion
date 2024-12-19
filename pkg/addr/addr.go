// Copyright 2023 SCION Association
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
	"net"
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// Addr is a full SCION address, composed of ISD, AS and Host part.
type Addr struct {
	IA   IA
	Host Host
}

// ParseAddr parses s as an address in the format <ISD>-<AS>,<Host>,
// returning the result as an Addr.
func ParseAddr(s string) (Addr, error) {
	comma := strings.IndexByte(s, ',')
	if comma < 0 {
		return Addr{}, serrors.New("invalid address: expected comma", "value", s)
	}
	ia, err := ParseIA(s[0:comma])
	if err != nil {
		return Addr{}, err
	}
	h, err := ParseHost(s[comma+1:])
	if err != nil {
		return Addr{}, err
	}
	return Addr{IA: ia, Host: h}, nil
}

// MustParseAddr calls ParseAddr(s) and panics on error.
// It is intended for use in tests with hard-coded strings.
func MustParseAddr(s string) Addr {
	a, err := ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func (a Addr) String() string {
	return fmt.Sprintf("%s,%s", a.IA, a.Host)
}

// Set implements flag.Value interface
func (a *Addr) Set(s string) error {
	pA, err := ParseAddr(s)
	if err != nil {
		return err
	}
	*a = pA
	return nil
}

func (a Addr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a *Addr) UnmarshalText(b []byte) error {
	return a.Set(string(b))
}

// ParseAddrPort parses s as a SCION address with a port, in the format
//
//	[<ISD>-<AS>,<Host>]:<Port>.
//
// Examples:
//   - [isd-as,svc]:port        (e.g., [1-ff00:0:110,CS]:80)
//   - [isd-as,ipv4]:port       (e.g., [1-ff00:0:110,192.0.2.1]:80)
//   - [isd-as,ipv6%zone]:port  (e.g., [1-ff00:0:110,2001:DB8::1%zone]:80)
//
// EXPERIMENTAL: This API is experimental. It may be changed to return a
// combined AddrPort type instead.
func ParseAddrPort(s string) (Addr, uint16, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, 0, serrors.Wrap("invalid address: split host:port", err, "addr", s)
	}
	a, err := ParseAddr(host)
	if err != nil {
		return Addr{}, 0, serrors.Wrap("invalid address: host invalid", err, "host", host)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Addr{}, 0, serrors.Wrap("invalid address: port invalid", err, "port", port)
	}
	return a, uint16(p), nil
}

// FormatAddrPort formats an Addr with a port to the format
//
//	[<ISD>-<AS>,<Host>]:<Port>.
//
// EXPERIMENTAL: This API is experimental. It may be changed to a String()
// function an a combined AddrPort type instead.
func FormatAddrPort(a Addr, port uint16) string {
	return fmt.Sprintf("[%s]:%d", a, port)
}
