// Copyright 2026 ETH Zurich
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
	"crypto/x509"
	"fmt"
	"slices"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	storage "github.com/scionproto/scion/private/storage/trust"
	"github.com/scionproto/scion/private/trust"
)

type MemoryDB struct {
	mtx    sync.RWMutex
	chains map[string]db_chain
	trcs   map[cppki.TRCID]db_trc
}

type db_chain struct {
	ia           addr.IA
	validity     cppki.Validity
	subjectKeyID []byte
	asCert       []byte
	caCert       []byte
}

type db_trc struct {
	raw []byte
}

func NewTrustMemoryDB() *MemoryDB {
	return &MemoryDB{
		chains: make(map[string]db_chain),
		trcs:   make(map[cppki.TRCID]db_trc),
	}
}

func (m *MemoryDB) Chain(_ context.Context, chainID []byte) ([]*x509.Certificate, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	key := fmt.Sprintf("%x", chainID)
	chain, found := m.chains[key]
	if !found {
		return nil, serrors.New("no chain found matching chainID")
	}
	as, err := x509.ParseCertificate(chain.asCert)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(chain.caCert)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{as, ca}, nil
}

func (m *MemoryDB) Chains(_ context.Context, query trust.ChainQuery) (
	[][]*x509.Certificate, error) {

	m.mtx.RLock()
	defer m.mtx.RUnlock()
	var res [][]*x509.Certificate
	for _, chain := range m.chains {
		if len(query.SubjectKeyID) != 0 &&
			slices.Compare(chain.subjectKeyID, query.SubjectKeyID) != 0 {
			continue
		}
		if !query.Validity.IsZero() {
			if chain.validity.NotBefore.After(query.Validity.NotBefore) ||
				chain.validity.NotAfter.Before(query.Validity.NotAfter) {
				continue
			}
		}
		if query.IA.ISD() != 0 && chain.ia.ISD() != query.IA.ISD() {
			continue
		}
		if query.IA.AS() != 0 && chain.ia.AS() != query.IA.AS() {
			continue
		}
		as, err := x509.ParseCertificate(chain.asCert)
		if err != nil {
			return nil, err
		}
		ca, err := x509.ParseCertificate(chain.caCert)
		if err != nil {
			return nil, err
		}
		res = append(res, []*x509.Certificate{
			as, ca,
		})
	}
	return res, nil
}

func (m *MemoryDB) Close() error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	clear(m.chains)
	clear(m.trcs)
	return nil
}

func (m *MemoryDB) InsertChain(_ context.Context, chain []*x509.Certificate) (bool, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if len(chain) != 2 {
		return false, serrors.New("invalid chain length")
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return false, serrors.New("invalid AS cert")
	}
	chainID := storage.ChainID(chain)
	key := fmt.Sprintf("%x", chainID)
	_, found := m.chains[key]
	if found {
		// already in DB
		return false, nil
	}
	m.chains[key] = db_chain{
		ia: ia,
		validity: cppki.Validity{
			NotBefore: chain[0].NotBefore.UTC(),
			NotAfter:  chain[0].NotAfter.UTC(),
		},
		subjectKeyID: chain[0].SubjectKeyId,
		asCert:       chain[0].Raw,
		caCert:       chain[1].Raw,
	}
	return true, nil
}

func (m *MemoryDB) InsertTRC(_ context.Context, trc cppki.SignedTRC) (bool, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.trcs[trc.TRC.ID] = db_trc{trc.Raw}
	return true, nil
}

func (m *MemoryDB) SignedTRC(_ context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	if id.Base.IsLatest() != id.Serial.IsLatest() {
		return cppki.SignedTRC{}, serrors.New("unsupported TRC ID for query", "id", id)
	}
	if id.Base.IsLatest() {
		latestBase := scrypto.Version(0)
		latestSerial := scrypto.Version(0)
		var latest cppki.TRCID
		for trcid := range m.trcs {
			if trcid.ISD == id.ISD {
				if trcid.Base > latestBase ||
					(trcid.Base == latestBase && trcid.Serial > latestSerial) {
					latestBase = trcid.Base
					latestSerial = trcid.Serial
					latest = trcid
				}
			}
		}
		id = latest
	}
	raw, found := m.trcs[id]
	if !found {
		return cppki.SignedTRC{}, nil
	}
	trc, err := cppki.DecodeSignedTRC(raw.raw)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return trc, nil
}

func (m *MemoryDB) SignedTRCs(_ context.Context, query storage.TRCsQuery) (
	cppki.SignedTRCs, error) {

	m.mtx.RLock()
	defer m.mtx.RUnlock()
	var res cppki.SignedTRCs
	appendTRC := func(trc db_trc) error {
		curRes, err := cppki.DecodeSignedTRC(trc.raw)
		if err != nil {
			return err
		}
		res = append(res, curRes)
		return nil
	}
	tmp := make(map[addr.ISD]cppki.TRCID)
	if query.Latest {
		for trcid := range m.trcs {
			if len(query.ISD) > 0 && !slices.Contains(query.ISD, trcid.ISD) {
				continue
			}
			storedID, found := tmp[trcid.ISD]
			if !found {
				tmp[trcid.ISD] = trcid
			} else if trcid.Base > storedID.Base ||
				(trcid.Base == storedID.Base && trcid.Serial > storedID.Serial) {
				tmp[trcid.ISD] = trcid
			}
		}
		for _, trcid := range tmp {
			raw, found := m.trcs[trcid]
			if !found {
				continue
			}
			if err := appendTRC(raw); err != nil {
				return nil, err
			}
		}
	} else {
		for trcid, trc := range m.trcs {
			if len(query.ISD) > 0 && !slices.Contains(query.ISD, trcid.ISD) {
				continue
			}
			if err := appendTRC(trc); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}
