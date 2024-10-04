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

package trust

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

var (
	// ErrAlreadyExists indicates a file is ignored because the contents have
	// already been loaded previously.
	ErrAlreadyExists = serrors.New("already exists")
	// ErrOutsideValidity indicates a file is ignored because the current time
	// is outside of the certificates validity period.
	ErrOutsideValidity = serrors.New("outside validity")
)

// LoadResult indicates which files were loaded, which files were ignored.
type LoadResult struct {
	Loaded  []string
	Ignored map[string]error
}

// LoadChains loads all *.pem files located in a directory in the database after
// validating first that each one is a valid CP certificate chains. All *.pem
// files that are not valid chains are ignored.
func LoadChains(ctx context.Context, dir string, db DB) (LoadResult, error) {
	if _, err := os.Stat(dir); err != nil {
		return LoadResult{}, serrors.Wrap("stating directory", err, "dir", dir)
	}

	files, err := filepath.Glob(fmt.Sprintf("%s/*.pem", dir))
	if err != nil {
		return LoadResult{}, serrors.Wrap("searching for certificates", err, "dir", dir)
	}

	res := LoadResult{Ignored: map[string]error{}}
	// TODO(roosd): should probably be a transaction.
	for _, f := range files {
		chain, err := cppki.ReadPEMCerts(f)
		if err != nil {
			res.Ignored[f] = err
			continue
		}
		if err := cppki.ValidateChain(chain); err != nil {
			res.Ignored[f] = err
			continue
		}
		validity := cppki.Validity{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter}
		if !validity.Contains(time.Now()) {
			res.Ignored[f] = ErrOutsideValidity
			continue
		}
		ia, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			res.Ignored[f] = err
			continue
		}
		trcs, _, err := activeTRCs(ctx, db, ia.ISD())
		if errors.Is(err, errNotFound) {
			res.Ignored[f] = serrors.New("TRC not found", "isd", ia.ISD())
			continue
		}
		if err != nil {
			return res, serrors.Wrap("loading TRC(s) to verify certificate chain", err,
				"file", f)

		}
		var verifyErrors serrors.List
		for _, trc := range trcs {
			opts := cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}
			if err := cppki.VerifyChain(chain, opts); err != nil {
				verifyErrors = append(verifyErrors, err)
			}
		}
		if len(verifyErrors) == len(trcs) {
			res.Ignored[f] = verifyErrors.ToError()
			continue
		}
		inserted, err := db.InsertChain(ctx, chain)
		if err != nil {
			return res, serrors.Wrap("inserting certificate chain", err, "file", f)
		}
		if !inserted {
			res.Ignored[f] = serrors.JoinNoStack(ErrAlreadyExists, err)
			continue
		}
		res.Loaded = append(res.Loaded, f)
	}
	return res, nil
}

// LoadTRCs loads all *.trc located in a directory in the database. This
// function exits on the first encountered error. TRCs with a not before time in
// the future are ignored.
//
// This function is not recommended for repeated use as it will read all TRC
// files in a directory on every invocation. Consider using a TRCLoader if you
// want to monitor a directory for new TRCs.
func LoadTRCs(ctx context.Context, dir string, db DB) (LoadResult, error) {
	return loadTRCs(ctx, dir, db, nil)
}

func loadTRCs(
	ctx context.Context,
	dir string,
	db DB,
	ignoreFiles map[string]struct{},
) (LoadResult, error) {
	if _, err := os.Stat(dir); err != nil {
		return LoadResult{}, serrors.WrapNoStack("stating directory", err, "dir", dir)
	}

	files, err := filepath.Glob(fmt.Sprintf("%s/*.trc", dir))
	if err != nil {
		return LoadResult{}, serrors.WrapNoStack("searching for TRCs", err, "dir", dir)
	}

	res := LoadResult{Ignored: map[string]error{}}
	// TODO(roosd): should probably be a transaction.
	for _, f := range files {
		// ignore as per request of the caller
		if _, ok := ignoreFiles[f]; ok {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			return res, serrors.WrapNoStack("reading TRC", err, "file", f)
		}
		block, _ := pem.Decode(raw)
		if block != nil && block.Type == "TRC" {
			raw = block.Bytes
		}
		trc, err := cppki.DecodeSignedTRC(raw)
		if err != nil {
			return res, serrors.WrapNoStack("parsing TRC", err, "file", f)
		}
		if time.Now().Before(trc.TRC.Validity.NotBefore) {
			res.Ignored[f] = serrors.New("TRC in the future", "validity", trc.TRC.Validity)
			continue
		}
		inserted, err := db.InsertTRC(ctx, trc)
		if err != nil {
			return res, serrors.WrapNoStack("adding TRC to DB", err, "file", f)
		}
		if !inserted {
			res.Ignored[f] = ErrAlreadyExists
			continue
		}
		res.Loaded = append(res.Loaded, f)
	}
	return res, nil
}

// TRCLoader loads TRCs from a directory and stores them in the database. It
// tracks files that it has already loaded and does not load them again.
type TRCLoader struct {
	Dir string
	DB  DB

	seen map[string]struct{}
	mtx  sync.Mutex
}

// Load loads all TRCs from the directory into database. Files that have been
// loaded by a previous Load invocation are silently ignored.
func (l *TRCLoader) Load(ctx context.Context) (LoadResult, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if l.seen == nil {
		l.seen = make(map[string]struct{})
	}

	result, err := loadTRCs(ctx, l.Dir, l.DB, l.seen)
	for _, f := range result.Loaded {
		l.seen[f] = struct{}{}
	}
	for f, err := range result.Ignored {
		if errors.Is(err, ErrAlreadyExists) {
			l.seen[f] = struct{}{}
		}
	}
	return result, err
}
