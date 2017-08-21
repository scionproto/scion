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

// This file contains the Go representation of a Path Construction Beacon

package pcb

type Meta struct {
	Type    uint8
	Segment PathSegment `capnp:"pcb"`
}

type PathSegment struct {
	Info      []byte
	IfID      uint64
	ASEntries []ASEntry `capnp:"asms"`
	Exts      struct {
		Sibra []byte `capnp:"-"` // Omit SIBRA extension for now.
	}
}
