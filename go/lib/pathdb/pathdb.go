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

// This file contains the PathSegment Database frontend.

package pathdb

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/conn"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/pathdb/sqlite"
)

type DB struct {
	conn conn.Conn
}

// New creates a new or open an existing PathDB at a given path using the
// given backend.
func New(path string, backend string) (*DB, error) {
	db := &DB{}
	var err error
	switch backend {
	case "sqlite":
		db.conn, err = sqlite.New(path)
	default:
		return nil, common.NewBasicError("Unknown backend", nil, "backend", backend)
	}
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Insert inserts or updates a path segment. It returns the number of path segments
// that have been inserted/updated.
func (db *DB) Insert(pseg *seg.PathSegment, segTypes []seg.Type) (int, error) {
	return db.conn.Insert(pseg, segTypes)
}

// InsertWithCfgIDs inserts or updates a path segment with a set of HPCfgIDs. It
// returns the number of path segments that have been inserted/updated.
func (db *DB) InsertWithHPCfgIDs(pseg *seg.PathSegment,
	segTypes []seg.Type, hpCfgIDs []*query.HPCfgID) (int, error) {
	return db.conn.InsertWithHPCfgIDs(pseg, segTypes, hpCfgIDs)
}

// Delete deletes a path segment with a given ID. Returns the number of deleted
// path segments (0 or 1).
func (db *DB) Delete(segID common.RawBytes) (int, error) {
	return db.conn.Delete(segID)
}

// DeleteWithIntf deletes all path segments that contain a given interface. Returns
// the number of path segments deleted.
func (db *DB) DeleteWithIntf(intf query.IntfSpec) (int, error) {
	return db.conn.DeleteWithIntf(intf)
}

// Get returns all path segment(s) matching the parameters specified.
func (db *DB) Get(params *query.Params) ([]*query.Result, error) {
	return db.conn.Get(params)
}
