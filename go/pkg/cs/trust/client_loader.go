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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
)

// ClientLoader loads client chains from the given directory into the DB.
type ClientLoader struct {
	Dir      string
	ClientDB renewal.DB
}

// LoadClientChains loads the client chains into the DB.
func (l ClientLoader) LoadClientChains(ctx context.Context) error {
	if _, err := os.Stat(l.Dir); err != nil {
		return serrors.WithCtx(err, "dir", l.Dir)
	}
	files, err := filepath.Glob(fmt.Sprintf("%s/*.pem", l.Dir))
	if err != nil {
		return serrors.WithCtx(err, "dir", l.Dir)
	}
	ignored := make(map[string]error)
	var loaded []string
	for _, f := range files {
		chain, err := cppki.ReadPEMCerts(f)
		if err != nil {
			ignored[f] = err
			continue
		}
		if err := cppki.ValidateChain(chain); err != nil {
			ignored[f] = err
			continue
		}
		inserted, err := l.ClientDB.InsertClientChain(ctx, chain)
		if err != nil {
			return serrors.WrapStr("inserting client chain", err, "file", f)
		}
		if !inserted {
			log.FromCtx(ctx).Debug("Ignoring existing client chain", "file", f)
			continue
		}
		loaded = append(loaded, f)

	}
	if len(loaded) != 0 {
		log.FromCtx(ctx).Info("Client chains loaded", "files", strings.Join(loaded, ", "))
	}
	for f, r := range ignored {
		log.FromCtx(ctx).Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}
	return nil
}
