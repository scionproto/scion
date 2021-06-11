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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
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
		return LoadResult{}, serrors.WithCtx(err, "dir", dir)
	}

	files, err := filepath.Glob(fmt.Sprintf("%s/*.pem", dir))
	if err != nil {
		return LoadResult{}, serrors.WithCtx(err, "dir", dir)
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
		tid := cppki.TRCID{
			ISD:    ia.I,
			Serial: scrypto.LatestVer,
			Base:   scrypto.LatestVer,
		}
		trc, err := db.SignedTRC(ctx, tid)
		if err != nil {
			return res, serrors.WrapStr("loading TRC to verify certificate chain", err, "file", f)
		}
		if trc.IsZero() {
			res.Ignored[f] = serrors.New("TRC not found", "isd", ia.I)
			continue
		}
		opts := cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}
		if err := cppki.VerifyChain(chain, opts); err != nil {
			res.Ignored[f] = err
			continue
		}
		inserted, err := db.InsertChain(ctx, chain)
		if err != nil {
			return res, serrors.WrapStr("inserting certificate chain", err, "file", f)
		}
		if !inserted {
			res.Ignored[f] = serrors.Wrap(ErrAlreadyExists, err)
			continue
		}
		res.Loaded = append(res.Loaded, f)
	}
	return res, nil
}

// LoadTRCs loads all *.trc located in a directory in the database. This
// function exits on the first encountered error. TRCs with a not before time
// in the future are ignored.
func LoadTRCs(ctx context.Context, dir string, db DB) (LoadResult, error) {
	if _, err := os.Stat(dir); err != nil {
		return LoadResult{}, serrors.WithCtx(err, "dir", dir)
	}

	files, err := filepath.Glob(fmt.Sprintf("%s/*.trc", dir))
	if err != nil {
		return LoadResult{}, serrors.WithCtx(err, "dir", dir)
	}

	res := LoadResult{Ignored: map[string]error{}}
	// TODO(roosd): should probably be a transaction.
	for _, f := range files {
		raw, err := ioutil.ReadFile(f)
		if err != nil {
			return res, serrors.WithCtx(err, "file", f)
		}
		block, _ := pem.Decode(raw)
		if block != nil && block.Type == "TRC" {
			raw = block.Bytes
		}
		trc, err := cppki.DecodeSignedTRC(raw)
		if err != nil {
			return res, serrors.WithCtx(err, "file", f)
		}
		if time.Now().Before(trc.TRC.Validity.NotBefore) {
			res.Ignored[f] = serrors.New("TRC in the future", "validity", trc.TRC.Validity)
			continue
		}
		inserted, err := db.InsertTRC(ctx, trc)
		if err != nil {
			return res, serrors.WithCtx(err, "file", f)
		}
		if !inserted {
			res.Ignored[f] = serrors.Wrap(ErrAlreadyExists, err)
			continue
		}
		res.Loaded = append(res.Loaded, f)
	}
	return res, nil
}
