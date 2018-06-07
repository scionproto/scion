// Copyright 2018 ETH Zurich
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

package store

import (
	"context"
	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/sqlite"
)

const (
	InvalidDBPath       = "Invalid path for database"
	UnableToPrepareStmt = "Unable to prepare stmt"
	UnableToExecuteStmt = "Unable to execute stmt"
)

const (
	Path          = "drkeyDB.sqlite3"
	SchemaVersion = 1
	Schema        = `
	CREATE TABLE DRKeyLvl1 (
		SrcIsdID 	INTEGER NOT NULL,
		SrcAsID 	INTEGER NOT NULL,
		DstIsdID 	INTEGER NOT NULL,
		DstAsID 	INTEGER NOT NULL,
		ExpTime 	INTEGER NOT NULL,
		Key 		TEXT NOT NULL,
		PRIMARY KEY (SrcIsdID, SrcAsID, DstIsdID, DstAsID, ExpTime)
	);

	CREATE TABLE DRKeyLvl2 (
		Protocol	TEXT NOT NULL,
		Type		INTEGER NOT NULL,
		SrcIsdID 	INTEGER NOT NULL,
		SrcAsID 	INTEGER NOT NULL,
		DstIsdID 	INTEGER NOT NULL,
		DstAsID 	INTEGER NOT NULL,
		AddIsdID	INTEGER,
		AddAsID		INTEGER,
		SrcHostIP 	TEXT,
		DstHostIP	TEXT,
		AddHostIP	TEXT,
		ExpTime 	INTEGER NOT NULL,
		Key 		TEXT NOT NULL,
		PRIMARY KEY (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID, AddIsdID, AddAsID,
			SrcHostIP, DstHostIP, AddHostIP, ExpTime)
	);`

	DRKeyLvl1Table = "DRKeyLvl1"
	DRKeyLvl2Table = "DRKeyLvl2"
)

const (
	getDRKeyLvl1 = `
		SELECT Key FROM DRKeyLvl1 WHERE SrcIsdID=? AND SrcAsID=? AND DstIsdID=? AND DstAsID=? 
		AND ?<=ExpTime
	`
	insertDRKeyLvl1 = `
		INSERT OR IGNORE INTO DRKeyLvl1 (SrcIsdID, SrcAsID, DstIsdID, DstAsID, ExpTime, Key)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	removeOutdatedDRKeyLvl1 = `
		DELETE FROM DRKeyLvl1 WHERE ?>ExpTime
	`
	getDRKeyLvl2 = `
		SELECT Key FROM DRKeyLvl2 WHERE Protocol=? AND Type=? AND SrcIsdID=? AND SrcAsID=? AND 
		DstIsdID=? AND DstAsID=? AND AddIsdID=? AND AddAsID=? AND SrcHostIP=? AND DstHostIP=? AND
		AddHostIP=? AND ?<=ExpTime
	`
	insertDRKeyLvl2 = `
		INSERT OR IGNORE INTO DRKeyLvl2 (Protocol, Type, SrcIsdID, SrcAsID, DstIsdID, DstAsID, 
		AddIsdID, AddAsID, SrcHostIP, DstHostIP, AddHostIP, ExpTime, Key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	removeOutdatedDRKeyLvl2 = `
		DELETE FROM DRKeyLvl2 WHERE ?>ExpTime
	`
)

// DB is a database containing first order and second order DRKeys, stored in JSON format.
// On errors, GetXxx methods return nil and the error. If no error occurred,
// but the database query yielded 0 results, the first returned value is nil.
// GetXxxCtx methods are the context equivalents of GetXxx.
type DB struct {
	db                          *sql.DB
	getDRKeyLvl1Stmt            *sql.Stmt
	insertDRKeyLvl1Stmt         *sql.Stmt
	removeOutdatedDRKeyLvl1Stmt *sql.Stmt
	getDRKeyLvl2Stmt            *sql.Stmt
	insertDRKeyLvl2Stmt         *sql.Stmt
}

// New creates a database and prepares all prepares all statements.
func New(path string) (*DB, error) {
	if len(path) <= 0 {
		return nil, common.NewBasicError(InvalidDBPath, nil)
	}
	var err error
	db := &DB{}
	if db.db, err = sqlite.New(path, Schema, SchemaVersion); err != nil {
		return nil, err
	}
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			db.db.Close()
		}
	}()
	if db.getDRKeyLvl1Stmt, err = db.db.Prepare(getDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if db.insertDRKeyLvl1Stmt, err = db.db.Prepare(insertDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if db.removeOutdatedDRKeyLvl1Stmt, err = db.db.Prepare(removeOutdatedDRKeyLvl1); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if db.getDRKeyLvl2Stmt, err = db.db.Prepare(getDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	if db.insertDRKeyLvl2Stmt, err = db.db.Prepare(insertDRKeyLvl2); err != nil {
		return nil, common.NewBasicError(UnableToPrepareStmt, err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.db.Close()
}

// GetDRKeyLvl1 takes an pointer to a first level DRKey and a timestamp at which the DRKey should be
// valid and returns the corresponding first level DRKey.
func (db *DB) GetDRKeyLvl1(key *drkey.DRKeyLvl1, valTime uint32) (common.RawBytes, error) {
	return db.GetDRKeyLvl1Ctx(context.Background(), key, valTime)
}

// GetDRKeyLvl1Ctx is the context-aware version of GetDRKeyLvl1.
func (db *DB) GetDRKeyLvl1Ctx(ctx context.Context, key *drkey.DRKeyLvl1,
	valTime uint32) (common.RawBytes, error) {
	var drkeyRaw common.RawBytes
	err := db.getDRKeyLvl1Stmt.QueryRowContext(ctx, key.SrcIa.I, key.SrcIa.A, key.DstIa.I,
		key.DstIa.A, valTime).Scan(&drkeyRaw)
	if err != nil {
		return nil, common.NewBasicError(UnableToExecuteStmt, err)
	}
	return drkeyRaw, nil
}

// InsertDRKeyLvl1 inserts a first level DRKey and returns the number of affected rows.
func (db *DB) InsertDRKeyLvl1(key *drkey.DRKeyLvl1, expTime uint32) (int64, error) {
	return db.InsertDRKeyLvl1Ctx(context.Background(), key, expTime)
}

// InsertDRKeyLvl1Ctx is the context-aware version of InsertDRKey.
func (db *DB) InsertDRKeyLvl1Ctx(ctx context.Context, key *drkey.DRKeyLvl1,
	expTime uint32) (int64, error) {
	res, err := db.insertDRKeyLvl1Stmt.ExecContext(ctx, key.SrcIa.I, key.SrcIa.A, key.DstIa.I,
		key.DstIa.A, expTime, key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RemoveOutdatedDRKeyLvl1 removes all expired first level DRKeys.
func (db *DB) RemoveOutdatedDRKeyLvl1(expTime uint32) (int64, error) {
	return db.RemoveOutdatedDRKeyLvl1Ctx(context.Background(), expTime)
}

// RemoveOutdatedDRKeyLvl1Ctx is the context-aware version of InsertDRKey.
func (db *DB) RemoveOutdatedDRKeyLvl1Ctx(ctx context.Context, expTime uint32) (int64, error) {
	res, err := db.removeOutdatedDRKeyLvl1Stmt.ExecContext(ctx, expTime)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetDRKeyLvl2 takes a source, destination and additional ISD-AS, a source, destination and
// additional host, and a timestamp at which the DRKey should be valid and
// returns a second level DRKey of the request type
func (db *DB) GetDRKeyLvl2(key *drkey.DRKeyLvl2, valTime uint32) (common.RawBytes, error) {
	return db.GetDRKeyLvl2Ctx(context.Background(), key, valTime)
}

// GetDRKeyLvl2Ctx is the context-aware version of GetDRKeyLvl2.
func (db *DB) GetDRKeyLvl2Ctx(ctx context.Context, key *drkey.DRKeyLvl2,
	valTime uint32) (common.RawBytes, error) {
	var drkeyRaw common.RawBytes
	err := db.getDRKeyLvl2Stmt.QueryRowContext(ctx, key.Proto, key.Type, key.SrcIa.I, key.SrcIa.A,
		key.DstIa.I, key.DstIa.A, key.AddIa.I, key.AddIa.A, key.SrcHost, key.DstHost, key.AddHost,
		valTime).Scan(&drkeyRaw)
	if err != nil {
		return nil, common.NewBasicError(UnableToExecuteStmt, err)
	}
	return drkeyRaw, nil
}

// InsertDRKeyLvl2 inserts a second-level DRKey.
func (db *DB) InsertDRKeyLvl2(key *drkey.DRKeyLvl2, expTime uint32) (int64, error) {
	return db.InsertDRKeyLvl2Ctx(context.Background(), key, expTime)
}

// InsertDRKeyLvl2Ctx is the context-aware version of InsertDRKeyLvl2.
func (db *DB) InsertDRKeyLvl2Ctx(ctx context.Context, key *drkey.DRKeyLvl2,
	expTime uint32) (int64, error) {
	res, err := db.insertDRKeyLvl2Stmt.ExecContext(ctx, key.Proto, key.Type, key.SrcIa.I,
		key.SrcIa.A, key.DstIa.I, key.DstIa.A, key.AddIa.I, key.AddIa.A, key.SrcHost, key.DstHost,
		key.AddHost, expTime, key.Key)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
