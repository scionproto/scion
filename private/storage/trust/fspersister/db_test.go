// Copyright 2020 Anapaya Systems
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

package fspersister_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/storage/trust/dbtest"
	"github.com/scionproto/scion/private/storage/trust/fspersister"
	"github.com/scionproto/scion/private/storage/trust/sqlite"
)

const (
	testTrcsDir = "testdata/overthenetwork/"
)

type DB struct {
	storage.TrustDB
	Dir     string
	cleanup []func()
}

func (db *DB) Prepare(t *testing.T, _ context.Context) {
	dir, cleanupF := xtest.MustTempDir("", "tmp")
	db.prepare(t, dir)
	db.cleanup = append(db.cleanup, cleanupF)
}

func (db *DB) prepare(t *testing.T, dbDir string) {
	sqliteDB, err := sqlite.New("file::memory:")
	require.NoError(t, err)
	*db = DB{
		TrustDB: fspersister.WrapDB(sqliteDB, fspersister.Config{
			TRCDir: dbDir,
		}),
		Dir: dbDir,
	}
}

func TestDB(t *testing.T) {
	testDB := &DB{}
	dbtest.Run(t, testDB, dbtest.Config{})
	for _, cleanup := range testDB.cleanup {
		cleanup()
	}
}

func TestInsertTRCWithFSPersistenceBadCfg(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testDB := &DB{}
	testDB.prepare(t, "./non-existing-path")
	t.Run(
		"insert signed TRC with invalid configured dir doesn't fail on database insert",
		func(t *testing.T) {
			SignedTRC, _ := getTRC(t, "ISD1-B1-S2.trc", testDB.Dir)

			in, err := testDB.InsertTRC(ctx, SignedTRC)
			require.NoError(t, err)
			require.True(t, in)

			filePathAfterInsert := filepath.Join(testDB.Dir, "ISD1-B1-S2.trc")
			_, readErr := os.ReadFile(filePathAfterInsert)
			require.Error(t, readErr)
		})

}

func TestInsertTRCWithFSPersistence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testDB := &DB{}
	testDB.Prepare(t, ctx)

	t.Run("insert TRC not present in neither DB nor FS", func(t *testing.T) {
		SignedTRC, persistedTrcPath := getTRC(t, "ISD1-B1-S1.trc", testDB.Dir)
		in, err := testDB.InsertTRC(ctx, SignedTRC)
		require.NoError(t, err)
		require.True(t, in)

		persistedTRC := xtest.LoadTRC(t, persistedTrcPath)
		require.Equal(t, SignedTRC, persistedTRC)
	})

	t.Run("insert TRC already present in DB and FS", func(t *testing.T) {
		SignedTRC, persistedTrcPath := getTRC(t, "ISD1-B1-S1.trc", testDB.Dir)
		mtimeBeforeInsert := getModTime(t, persistedTrcPath)

		persistedTRC := xtest.LoadTRC(t, persistedTrcPath)
		require.Equal(t, SignedTRC, persistedTRC)

		in, err := testDB.InsertTRC(ctx, SignedTRC)
		require.NoError(t, err)
		require.False(t, in)

		mtimeAfterInsert := getModTime(t, persistedTrcPath)
		require.Equal(t, mtimeBeforeInsert, mtimeAfterInsert)

		persistedTRC = xtest.LoadTRC(t, persistedTrcPath)
		require.Equal(t, SignedTRC, persistedTRC)
	})

	t.Run("insert TRC not present in DB but present on FS", func(t *testing.T) {
		SignedTRC, persistedTrcPath := getTRC(t, "ISD2-B1-S1.trc", testDB.Dir)
		require.NoError(t, os.WriteFile(persistedTrcPath, SignedTRC.Raw, 0644))
		mtimeBeforeInsert := getModTime(t, persistedTrcPath)

		in, err := testDB.InsertTRC(ctx, SignedTRC)
		require.NoError(t, err)
		require.True(t, in)

		mtimeAfterInsert := getModTime(t, persistedTrcPath)
		require.Equal(t, mtimeBeforeInsert, mtimeAfterInsert)
	})

	t.Run("insert TRC that is already present in DB but not on FS", func(t *testing.T) {
		SignedTRC, persistedTrcPath := getTRC(t, "ISD1-B1-S1.trc", testDB.Dir)
		err := os.Remove(persistedTrcPath)
		require.NoError(t, err)
		in, err := testDB.InsertTRC(ctx, SignedTRC)
		require.NoError(t, err)
		require.False(t, in)

		persistedTRC := xtest.LoadTRC(t, persistedTrcPath)
		require.Equal(t, SignedTRC, persistedTRC)
	})

	for _, cleanup := range testDB.cleanup {
		cleanup()
	}
}

func getModTime(t *testing.T, file string) int64 {
	f, err := os.Open(file)
	require.NoError(t, err)
	defer f.Close()

	info, err := f.Stat()
	require.NoError(t, err)
	return info.ModTime().Unix()
}

func getTRC(t *testing.T, trcName, persistDir string) (cppki.SignedTRC, string) {
	testTrcPath := filepath.Join(testTrcsDir, trcName)
	trc := xtest.LoadTRC(t, testTrcPath)
	persistedTrcPath := filepath.Join(persistDir, trcName)
	return trc, persistedTrcPath
}
