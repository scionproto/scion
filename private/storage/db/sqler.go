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

package db

import (
	"context"
	"database/sql"

	"github.com/scionproto/scion/pkg/private/serrors"
)

var _ Sqler = (*sql.DB)(nil)
var _ Sqler = (*sql.Tx)(nil)

// Sqler contains the common functions of *sql.DB and *sql.Tx.
type Sqler interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

// DoInTx executes the given action in a transaction. If db is already a transaction the action is
// executed in the existing transaction, the transaction is not modified. If db is a "normal" db, a
// transaction is created and action is executed in it. If action errors the created transaction is
// rollbacked, otherwise it is committed.
func DoInTx(ctx context.Context, db Sqler, action func(context.Context, *sql.Tx) error) error {
	tx, ok := db.(*sql.Tx)
	if ok {
		return action(ctx, tx)
	}
	var err error
	if tx, err = db.(*sql.DB).BeginTx(ctx, nil); err != nil {
		return NewTxError("create tx", err)
	}
	if err := action(ctx, tx); err != nil {
		return serrors.Join(err, tx.Rollback())
	}
	if err := tx.Commit(); err != nil {
		return serrors.Join(NewTxError("commit", err), tx.Rollback())
	}
	return nil
}

// DeleteInTx executes delFunc in a transaction and returns the affected rows.
func DeleteInTx(ctx context.Context, db Sqler,
	delFunc func(tx *sql.Tx) (sql.Result, error)) (int, error) {

	var res sql.Result
	err := DoInTx(ctx, db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		res, err = delFunc(tx)
		return err
	})
	if err != nil {
		return 0, NewWriteError("delete in tx", err)
	}
	deleted, _ := res.RowsAffected()
	return int(deleted), nil
}
