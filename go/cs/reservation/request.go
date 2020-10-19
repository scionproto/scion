// Copyright 2020 ETH Zurich, Anapaya Systems
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

package reservation

import (
	"github.com/scionproto/scion/go/lib/serrors"
)

// RequestMetadata contains information about the request, such as its forwarding path.
// This base struct can be used by any request or response packets.
type RequestMetadata struct {
	path ColibriPath // the path the packet came / will go with
}

// NewRequestMetadata constructs the base Request type.
func NewRequestMetadata(path ColibriPath) (*RequestMetadata, error) {
	if path == nil {
		return nil, serrors.New("new request with nil path")
	}
	return &RequestMetadata{
		path: path.Copy(),
	}, nil
}

// Path returns the ColibriPath in this metadata.
func (m *RequestMetadata) Path() ColibriPath {
	return m.path
}

// IsLastAS returns true if this hop is the last one (this AS is the destination).
func (m *RequestMetadata) IsLastAS() bool {
	return m.path.IndexOfCurrentHop() == m.path.NumberOfHops()-1
}
