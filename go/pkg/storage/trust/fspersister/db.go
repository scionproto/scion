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

package fspersister

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/pkg/storage"
	"github.com/scionproto/scion/go/pkg/trust"
)

const (
	WriteSuccess = prom.Success
	WriteError   = "err_write"
	StatError    = "err_stat"
)

type db struct {
	storage.TrustDB
	cfg Config
}

// Config configures the wrapped trust database that persists
// TRCs on the local filesystem of the CS.
type Config struct {
	// TRCDir is the filesystem path where the TRCs will be persisted.
	TRCDir string
	// Metrics holds the metrics for the wrapped db.
	Metrics Metrics
}

type Metrics struct {
	TRCFileWriteSuccesses metrics.Counter
	TRCFileWriteErrors    metrics.Counter
	TRCFileStatErrors     metrics.Counter
}

var _ (trust.DB) = (*db)(nil)

// WrapDB wraps the given trust database into one that also persists
// the TRCs on the local filesystem of the running CS.
func WrapDB(trustDB storage.TrustDB, cfg Config) storage.TrustDB {
	return &db{
		TrustDB: trustDB,
		cfg:     cfg,
	}
}

func (db *db) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	logger := log.FromCtx(ctx)
	inserted, err := db.TrustDB.InsertTRC(ctx, trc)
	if err != nil {
		return inserted, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "TRC",
		Bytes: trc.Raw,
	})
	if encoded == nil {
		panic("failed to encode TRC")
	}

	// We assume that any TRC file present on the filesystem is not
	// corrupt and named properly, therefore no more checks besides
	// file existence are necessary
	file := filepath.Join(db.cfg.TRCDir, trcFileName(trc.TRC.ID))
	if _, statErr := os.Stat(file); errors.Is(statErr, os.ErrNotExist) {
		if writeErr := os.WriteFile(file, encoded, 0644); writeErr != nil {
			log.SafeInfo(logger, "Failed to write TRC to disk",
				"err", writeErr,
				"trc", trc.TRC.ID,
				"filename", file,
			)
			metrics.CounterInc(db.cfg.Metrics.TRCFileWriteErrors)
		} else {
			metrics.CounterInc(db.cfg.Metrics.TRCFileWriteSuccesses)
		}
	} else if statErr != nil {
		log.SafeInfo(logger, "Failed to stat TRC file on disk", "err", statErr)
		metrics.CounterInc(db.cfg.Metrics.TRCFileStatErrors)
	}
	return inserted, err
}

func trcFileName(id cppki.TRCID) string {
	return fmt.Sprintf("ISD%d-B%d-S%d.trc", id.ISD, id.Base, id.Serial)
}
