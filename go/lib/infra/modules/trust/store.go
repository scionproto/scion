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

package trust

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Store keeps track of the control-plane PKI crypto material.
type Store struct {
	Inspector
	CryptoProvider
	Inserter Inserter
	DB       DB
}

// NewTRCReqHandler returns an infra.Handler for TRC requests coming from a
// peer, backed by the trust store. The configured recurser defines whether the
// trust store is allowed to issue new TRC requests over the network.  This
// method should only be used when servicing requests coming from remote nodes.
func (s Store) NewTRCReqHandler(ia addr.IA) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &trcReqHandler{
			request:  r,
			provider: s.CryptoProvider,
			ia:       ia,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// NewChainReqHandler returns an infra.Handler for Certificate Chain requests
// coming from a peer, backed by the trust store. The configured recurser
// defines whether the trust store is allowed to issue new TRC and certificate
// chain requests over the network. This method should only be used when
// servicing requests coming from remote nodes.
func (s Store) NewChainReqHandler(ia addr.IA) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := chainReqHandler{
			request:  r,
			provider: s.CryptoProvider,
			ia:       ia,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// NewTRCPushHandler returns an infra.Handler for TRC pushes coming from a peer,
// backed by the trust store. TRCs are pushed by local BSes and PSes. Pushes are
// allowed from all local AS sources.
func (s Store) NewTRCPushHandler(ia addr.IA) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := trcPushHandler{
			request:  r,
			provider: s.CryptoProvider,
			inserter: s.Inserter,
			ia:       ia,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// NewChainPushHandler returns an infra.Handler for Certificate Chain pushes
// coming from a peer, backed by the trust store. Certificate chains are pushed
// by other ASes during core registration, or the local BSes and PSes. Pushes
// are allowed from all local ISD sources.
func (s Store) NewChainPushHandler(ia addr.IA) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := chainPushHandler{
			request:  r,
			provider: s.CryptoProvider,
			inserter: s.Inserter,
			ia:       ia,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// LoadCryptoMaterial loads the crypto material from the file system and
// populates the trust database.
func (s Store) LoadCryptoMaterial(ctx context.Context, dir string) error {
	if err := s.LoadTRCs(ctx, dir); err != nil {
		return err
	}
	if err := s.LoadChains(ctx, dir); err != nil {
		return err
	}
	return nil
}

// LoadTRCs loads the TRCs from the file system. This call ensures that the
// hashes match for TRCs that are already in the database. Before insertion,
// TRCs are verified.
func (s Store) LoadTRCs(ctx context.Context, dir string) error {
	files, err := filepath.Glob(fmt.Sprintf("%s/ISD*-V*.trc", dir))
	if err != nil {
		panic(err)
	}
	sort.Strings(files)
	for _, file := range files {
		if err := s.loadTRC(ctx, file); err != nil {
			return serrors.WrapStr("unable to load TRC", err, "file", file)
		}
	}
	return nil
}

func (s Store) loadTRC(ctx context.Context, file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	dec, err := decoded.DecodeTRC(raw)
	if err != nil {
		return err
	}
	unsafeInserter := DefaultInserter{
		BaseInserter: BaseInserter{
			DB:     s.DB,
			Unsafe: true,
		},
	}
	return unsafeInserter.InsertTRC(ctx, dec, s.DB.GetTRC)
}

// LoadChains loads the certificate chains from the file system. This call
// ensures that the hashes match for the chains that are already in the
// database. Before insertion, certificate chains are verified.
func (s Store) LoadChains(ctx context.Context, dir string) error {
	files, err := filepath.Glob(fmt.Sprintf("%s/ISD*-AS*-V*.crt", dir))
	if err != nil {
		panic(err)
	}
	sort.Strings(files)
	for _, file := range files {
		if err := s.loadChain(ctx, file); err != nil {
			return serrors.WithCtx(err, "file", file)
		}
	}
	return nil
}

func (s Store) loadChain(ctx context.Context, file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	dec, err := decoded.DecodeChain(raw)
	if err != nil {
		return err
	}
	unsafeInserter := DefaultInserter{
		BaseInserter: BaseInserter{
			DB:     s.DB,
			Unsafe: true,
		},
	}
	return unsafeInserter.InsertChain(ctx, dec, s.DB.GetTRC)
}
