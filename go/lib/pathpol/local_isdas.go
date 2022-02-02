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

// LocalISDAS is a path policy that checks whether the first hop in the path (local AS) belongs
// to the specified set.
type LocalISDAS struct {
	AllowedIAs []addr.IA
}

func (li *LocalISDAS) Eval(paths []snet.Path) []snet.Path {
	var result []snet.Path
	for _, path := range paths {
		if len(path.Metadata().Interfaces) == 0 {
			continue
		}
		ia := path.Metadata().Interfaces[0].IA
		for _, allowedIA := range li.AllowedIAs {
			if ia == allowedIA {
				result = append(result, path)
				break
			}
		}
	}
	return result
}

func (li *LocalISDAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(li.AllowedIAs)
}

func (li *LocalISDAS) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &li.AllowedIAs)
}
