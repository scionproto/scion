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

package pathpol

import (
	"encoding/json"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// RemoteISDAS is a path policy that checks whether the last hop in the path (remote AS) satisfies
// the supplied rules. Rules are evaluated in order and first that matches the remote ISD-AS wins.
// If in the winnig rule Reject is set to true, then the path will rejected by the policy,
// otherwise it will be accepted. If no rule matches the path will be rejected.
type RemoteISDAS struct {
	Rules []ISDASRule
}

type ISDASRule struct {
	IA     addr.IA `json:"isd_as,omitempty"`
	Reject bool    `json:"reject,omitempty"`
}

func (ri *RemoteISDAS) Eval(paths []snet.Path) []snet.Path {
	var result []snet.Path
	for _, path := range paths {
		if len(path.Metadata().Interfaces) == 0 {
			continue
		}
		ia := path.Destination()
		for _, rule := range ri.Rules {
			if matchISDAS(rule.IA, ia) {
				if !rule.Reject {
					result = append(result, path)
				}
				break
			}
		}
	}
	return result
}

func matchISDAS(rule addr.IA, ia addr.IA) bool {
	if rule.ISD() != 0 && rule.ISD() != ia.ISD() {
		return false
	}
	if rule.AS() != 0 && rule.AS() != ia.AS() {
		return false
	}
	return true
}

func (ri *RemoteISDAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(ri.Rules)
}

func (ri *RemoteISDAS) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &ri.Rules)
}
