// Copyright 2019 Anapaya Systems
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

package segfetcher

import "github.com/scionproto/scion/go/lib/addr"

// Request represents a path or segment request.
type Request struct {
	Src addr.IA
	Dst addr.IA
}

// IsZero returns whether the request is empty.
func (r Request) IsZero() bool {
	return r.Src.IsZero() && r.Dst.IsZero()
}

// RequestSet is a set of requests.
type RequestSet struct {
	Up    Request
	Cores Requests
	Down  Request
}

// IsEmpty returns whether the request set is empty.
func (r RequestSet) IsEmpty() bool {
	return r.Up.IsZero() && len(r.Cores) == 0 && r.Down.IsZero()
}

// Requests is a list of requests and provides some convenience methods on top
// of it.
type Requests []Request

// SrcIAs returns all unique sources in the request list.
func (r Requests) SrcIAs() []addr.IA {
	return r.extractIAs(func(req Request) addr.IA { return req.Src })
}

// DstIAs returns all unique destinations in the request list.
func (r Requests) DstIAs() []addr.IA {
	return r.extractIAs(func(req Request) addr.IA { return req.Dst })
}

func (r Requests) extractIAs(extract func(Request) addr.IA) []addr.IA {
	var ias []addr.IA
	addrs := make(map[addr.IA]struct{})
	for _, req := range r {
		ia := extract(req)
		if _, ok := addrs[ia]; !ok {
			addrs[ia] = struct{}{}
			ias = append(ias, ia)
		}
	}
	return ias
}
