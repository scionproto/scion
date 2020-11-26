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
	"crypto/x509"
	"errors"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/pkg/trust"
)

// CryptoLoader loads chains from the given directory or the DB.
type CryptoLoader struct {
	Dir string
	trust.DB
}

// Chains loads chains from disk, stores them to DB, and returns the result from
// DB. The fallback mode is always the result of the DB.
func (l CryptoLoader) Chains(ctx context.Context,
	query trust.ChainQuery) ([][]*x509.Certificate, error) {

	if err := l.loadTRCs(ctx); err != nil {
		log.FromCtx(ctx).Info("Failed to load TRCs from disk, continuing", "err", err)
	}
	r, err := trust.LoadChains(ctx, l.Dir, l.DB)
	if err != nil {
		log.FromCtx(ctx).Error("Failed to load chains from disk, using DB chains instead",
			"err", err)
		return l.DB.Chains(ctx, query)
	}
	if len(r.Loaded) > 0 {
		log.FromCtx(ctx).Info("Certificate chains loaded", "files", r.Loaded)
	}
	for f, reason := range r.Ignored {
		if errors.Is(reason, trust.ErrAlreadyExists) {
			log.FromCtx(ctx).Debug("Ignoring existing certificate chain", "file", f)
			continue
		}
		if errors.Is(reason, trust.ErrOutsideValidity) {
			log.FromCtx(ctx).Debug("Ignoring certificate chain outside validity", "file", f)
			continue
		}
		log.FromCtx(ctx).Info("Ignoring non-certificate chain", "file", f, "reason", reason)
	}
	return l.DB.Chains(ctx, query)
}

func (l CryptoLoader) loadTRCs(ctx context.Context) error {
	r, err := trust.LoadTRCs(ctx, l.Dir, l.DB)
	if err != nil {
		return err
	}
	if len(r.Loaded) > 0 {
		log.FromCtx(ctx).Info("TRCs loaded", "files", r.Loaded)
	}
	for f, reason := range r.Ignored {
		if errors.Is(reason, trust.ErrAlreadyExists) {
			log.FromCtx(ctx).Debug("Ignoring existing TRC", "file", f)
			continue
		}
		log.FromCtx(ctx).Info("Ignoring TRC", "file", f, "reason", reason)
	}
	return nil
}
