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
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/lib/pathdb/query"
)

type Conn interface {
	// Insert or update a path segment.
	Insert(*seg.PathSegment, []seg.Type) (int, error)
	// Insert or update a path segment with a given label.
	InsertWithHPCfgIDs(*seg.PathSegment, []seg.Type, []*query.HPCfgID) (int, error)
	// Deletes a path segment with a given ID. Returns the number of deleted
	// path segments (0 or 1).
	Delete(common.RawBytes) (int, error)
	// Deletes all path segments that contain a given interface. Returns the number
	// of path segments deleted.
	DeleteWithIntf(query.IntfSpec) (int, error)
	// Get returns all path segment(s) matching the parameters specified.
	Get(*query.Params) ([]*query.Result, error)
}
