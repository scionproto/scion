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
	"github.com/netsec-ethz/scion/go/lib/pathdb/conn"
)

type DB struct {
	conn *conn.Conn
}

func New(path string, backend string) (*DB, *common.Error) {
	db := &DB{}
	switch backend {
	case "sqlite":
		db.conn := sqlite.New(path)
	default:
		return nil, common.NewError(fmt.Sprintf("Unknown backend: '%s'", backend)
	}
}

func (db *DB) Insert(pseg *seg.PathSegment, segTypes []uint8) (int, *common.Error) {
	return db.conn.Insert(pseg, segTypes)
}

func (db *DB) InsertWithLabel(pseg *seg.PathSegment,
	segTypes []uint8, label uint64) (int, *common.Error) {
	return db.conn.InsertWithLabel(pseg, segTypes, label)
}

func (db *DB) Delete(segID common.RawBytes) (int, *common.Error) {
	return db.conn.Delete(segID)
}

func (db *DB) DeleteWithIntf(intf conn.IntfSpec) (int, *common.Error) {
	return db.conn.DeleteWithIntf(intf)
}

func (db *DB) Get(opt *conn.QueryOptions) ([]*seg.PathSegment, *common.Error) {
	return db.conn.Get(opt)
}