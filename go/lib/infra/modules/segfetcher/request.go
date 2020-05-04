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

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

// RequestState is the state the request is in.
type RequestState int

const (
	// Unresolved means the request is not yet resolved.
	Unresolved RequestState = iota
	// Fetch means the request needs to be fetched.
	Fetch
	// Loaded means the request has been fetched or loaded from the DB.
	Loaded
)

// Request represents a path or segment request.
type Request struct {
	Src     addr.IA
	Dst     addr.IA
	SegType proto.PathSegType
	State   RequestState
}

// IsZero returns whether the request is empty.
func (r Request) IsZero() bool {
	return r.Src.IsZero() && r.Dst.IsZero()
}

// ToSegReq returns the request as a path_mgmt segment request.
// XXX(matzf): could/should we include SegType in the wire request?
func (r Request) ToSegReq() *path_mgmt.SegReq {
	return &path_mgmt.SegReq{
		RawSrcIA: r.Src.IAInt(),
		RawDstIA: r.Dst.IAInt(),
	}
}

// Equal returns whether the two request refer to the same src/dst/type.
func (r Request) Equal(other Request) bool {
	return r.Src.Equal(other.Src) && r.Dst.Equal(other.Dst) && r.SegType == other.SegType
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

// IsEmpty returns whether the list of requests is empty.
func (r Requests) IsEmpty() bool {
	return len(r) == 0
}

// AllLoaded returns whether all entries in request have state loaded.
func (r Requests) AllLoaded() bool {
	for _, req := range r {
		if req.State != Loaded {
			return false
		}
	}
	return true
}

func (r Requests) extractIAs(extract func(Request) addr.IA) []addr.IA {
	set := make(map[addr.IA]struct{})
	for _, req := range r {
		set[extract(req)] = struct{}{}
	}
	ias := make([]addr.IA, 0, len(set))
	for ia := range set {
		ias = append(ias, ia)
	}
	return ias
}
