// Copyright 2019 ETH Zurich
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

package topology

import "github.com/scionproto/scion/go/lib/serrors"

var (
	errAtLeastOnePub         = serrors.New("underlay requires at least one public address")
	errUnsupportedUnderlay   = serrors.New("unsupported underlay")
	errInvalidPub            = serrors.New("invalid public address")
	errBindNotSupported      = serrors.New("bind addresses are not supported for this address type")
	errCustomUnderlayPort    = serrors.New("custom underlay port not supported")
	errUnderlayPort          = serrors.New("underlay port set for non-UDP underlay")
	errUnderlayAddrNotFound  = serrors.New("underlay address not found")
	errExpectedIPv4FoundIPv6 = serrors.New("expected IPv4 address, but found IPv6 address")
	errExpectedIPv6FoundIPv4 = serrors.New("expected IPv6 address, but found IPv4 address")
)
