// Copyright 2017 ETH Zurich
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

package sigjson

import (
	"encoding/json"
	"net"

	"github.com/scionproto/scion/go/lib/common"
)

// IPNet is custom type of net.IPNet, to allow custom unmarshalling.
type IPNet net.IPNet

func (in *IPNet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return common.NewBasicError("Unable to unmarshal IPnet from JSON", err, "raw", b)
	}
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return common.NewBasicError("Unable to parse IPnet string", err, "raw", s)
	}
	if !ip.Equal(ipnet.IP) {
		return common.NewBasicError("Network is not canonical (should not be host address).",
			nil, "raw", s)
	}
	*in = IPNet(*ipnet)
	return nil
}

func (in *IPNet) MarshalJSON() ([]byte, error) {
	return json.Marshal(in.String())
}

func (in *IPNet) IPNet() *net.IPNet {
	return (*net.IPNet)(in)
}

func (in *IPNet) String() string {
	return (*net.IPNet)(in).String()
}
