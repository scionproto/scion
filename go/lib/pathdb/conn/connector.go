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

// This file defines the Connector interface that all PathDB backends have to implement.

package conn

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
)

type IntfSpec struct {
	IA *addr.ISD_AS
	IfID uint64
}

type QueryOptions struct {
	SegID common.RawBytes
	SegTypes []uint8
	Labels []uint64
	Intfs []*IntfSpec
	StartsAt []*addr.ISD_AS
	EndsAt []*addr.ISD_AS
}

type Conn interface {
	// Open opens the pathdb storage at the given path.
	Open(string) *common.Error
	// Close closes the pathdb storage.
	Close() *common.Error
	// Setup sets up a pathdb storage.
	Setup() *common.Error

	// Insert or update a path segment.
	Insert(*seg.PathSegment, []uint8) (int, *common.Error)
	// Insert or update a path segment with a given label.
	InsertWithLabel(*seg.PathSegment, []uint8, uint64) (int, *common.Error)
	// Deletes a path segment with a given ID. Returns the number of deleted
	// path segments (0 or 1).
	Delete(common.RawBytes)) (int, *common.Error)
	// Deletes all path segments that contain a given interface. Returns the number
	// of path segments deleted.
	DeleteWithIntf(*addr.ISD_AS, uint64) (int, *common.Error)

	// Get returns all path segment(s) matching the QueryOptions specified.
	Get(*QueryOptions) ([]*seg.PathSegment, *common.Error)
}
