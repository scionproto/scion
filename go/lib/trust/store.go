// Copyright 2017 ETH Zurich
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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
)

type JSON interface {
	JSON(bool) ([]byte, error)
}

var _ JSON = (*cert.Chain)(nil)
var _ JSON = (*trc.TRC)(nil)

// Store handles storage and management of trust objects (certificate chains and TRCs)
type Store struct {
	// certDir is the certificate directory.
	certDir string
	// cacheDir is the directory to cache TRCs and certs in.
	cacheDir string
	// eName is the element name, used to generate cache file names.
	eName string
	// chainMap is a mapping form (ISD-AS, version) to certificate chain
	chainMap map[cert.Key]*cert.Chain
	// maxChainMap is a mapping from (ISD-AS) to max version.
	maxChainMap map[addr.IA]uint64
	// chainLock guards chainMap and maxChainMap.
	chainLock sync.RWMutex
	// trcMap is a mapping from (ISD, version) to corresponding TRC
	trcMap map[trc.Key]*trc.TRC
	// maxTrcMap is a mapping from (ISD) to max version.
	maxTrcMap map[addr.ISD]uint64
	// trcLock guards trcMap and maxTrcMap.
	trcLock sync.RWMutex
}

func NewStore(certDir, cacheDir, eName string) (*Store, error) {
	s := &Store{certDir: certDir, cacheDir: cacheDir, eName: eName,
		chainMap:    make(map[cert.Key]*cert.Chain),
		maxChainMap: make(map[addr.IA]uint64),
		trcMap:      make(map[trc.Key]*trc.TRC),
		maxTrcMap:   make(map[addr.ISD]uint64)}
	s.initChains()
	s.initTRCs()
	return s, nil
}

// initChains loads the certificate chain files from dir and cacheDir and populates chainMap
// as well as maxChainMap.
func (s *Store) initChains() error {
	files, err := filepath.Glob(fmt.Sprintf("%s/*.crt", s.certDir))
	if err != nil {
		return err
	}
	cachedFiles, err := filepath.Glob(fmt.Sprintf("%s/%s*.crt", s.cacheDir, s.eName))
	if err != nil {
		return err
	}

	for _, file := range append(files, cachedFiles...) {
		// FIXME(roosd): do not abort, but log errors
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}
		chain, err := cert.ChainFromRaw(raw, false)
		if err != nil {
			return err
		}
		if err = s.AddChain(chain, false); err != nil {
			return err
		}
	}
	return nil
}

// initTRCs loads the TRC files from dir and cacheDir and populates trcMap as well as maxTrcMap.
func (s *Store) initTRCs() error {
	files, err := filepath.Glob(fmt.Sprintf("%s/*.trc", s.certDir))
	if err != nil {
		return err
	}
	cachedFiles, err := filepath.Glob(fmt.Sprintf("%s/%s*.trc", s.cacheDir, s.eName))
	if err != nil {
		return err
	}
	for _, file := range append(files, cachedFiles...) {
		// FIXME(roosd): do not abort, but log errors
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}
		t, err := trc.TRCFromRaw(raw, false)
		if err != nil {
			return err
		}
		s.AddTRC(t, false)
	}
	return nil
}

// AddChain adds a trusted certificate chain to the store. If write is true, the certificate chain
// is written to the filesystem (in case it does not already exist).
func (s *Store) AddChain(chain *cert.Chain, write bool) error {
	ia, ver := chain.IAVer()
	key := *chain.Key()
	s.chainLock.Lock()
	if _, ok := s.chainMap[key]; !ok {
		s.chainMap[key] = chain
		if v, ok := s.maxChainMap[ia]; !ok || ver > v {
			s.maxChainMap[ia] = ver
		}
	}
	s.chainLock.Unlock()
	if write {
		return s.writeChain(chain)
	}
	return nil
}

// AddTRC adds a trusted TRC to the store. If write is true, the TRC is written to the filesystem
// (in case it does not already exist).
func (s *Store) AddTRC(trc *trc.TRC, write bool) error {
	isd, ver := trc.IsdVer()
	key := *trc.Key()
	s.trcLock.Lock()
	if _, ok := s.trcMap[key]; !ok {
		s.trcMap[key] = trc
		if v, ok := s.maxTrcMap[isd]; !ok || ver > v {
			s.maxTrcMap[isd] = ver
		}
	}
	s.trcLock.Unlock()
	if write {
		return s.writeTRC(trc)
	}
	return nil
}

// writeChain writes certificate chain to the filesystem, if it does not already exist.
func (s *Store) writeChain(chain *cert.Chain) error {
	ia, ver := chain.IAVer()
	name := fmt.Sprintf("%s-ISD%d-AS%d-V%d.crt", s.eName, ia.I, ia.A, ver)
	return s.writeJSON(chain, filepath.Join(s.cacheDir, name))
}

// writeTRC writes TRC to the filesystem, if it does not already exist.
func (s *Store) writeTRC(trc *trc.TRC) error {
	isd, ver := trc.IsdVer()
	name := fmt.Sprintf("%s-ISD%d-V%d.trc", s.eName, isd, ver)
	return s.writeJSON(trc, filepath.Join(s.cacheDir, name))
}

// writeJSON writes object of type JSON to the filesystem, if it does not already exist.
func (s *Store) writeJSON(j JSON, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		b, err := j.JSON(true)
		if err != nil {
			return err
		}
		if err = ioutil.WriteFile(path, b, 0644); err != nil {
			return err
		}
	}
	return nil
}

// GetChain returns the certificate chain for the specified values or nil, if it is not present.
func (s *Store) GetChain(ia addr.IA, ver uint64) *cert.Chain {
	s.chainLock.RLock()
	defer s.chainLock.RUnlock()
	return s.chainMap[*cert.NewKey(ia, ver)]
}

// GetNewestChain returns the certificate chain with the highest version for the specified ISD-AS.
func (s *Store) GetNewestChain(ia addr.IA) *cert.Chain {
	s.chainLock.RLock()
	defer s.chainLock.RUnlock()
	var chain *cert.Chain
	ver, ok := s.maxChainMap[ia]
	if ok {
		chain = s.chainMap[*cert.NewKey(ia, ver)]
	}
	return chain
}

// GetTRC returns the TRC for the specified values or nil, if it is not present.
func (s *Store) GetTRC(isd addr.ISD, ver uint64) *trc.TRC {
	s.trcLock.RLock()
	t := s.trcMap[*trc.NewKey(isd, ver)]
	s.trcLock.RUnlock()
	return t
}

// GetNewestTRC returns the TRC with the highest version for the specified ISD or nil, if there is
// no TRC present for that ISD.
func (s *Store) GetNewestTRC(isd addr.ISD) *trc.TRC {
	s.trcLock.RLock()
	defer s.trcLock.RUnlock()
	var t *trc.TRC
	ver, ok := s.maxTrcMap[isd]
	if ok {
		t = s.trcMap[*trc.NewKey(isd, ver)]
	}
	return t
}

// GetTRCList returns a slice of the highest TRCs for all present ISDs.
func (s *Store) GetTRCList() []*trc.TRC {
	s.trcLock.RLock()
	defer s.trcLock.RUnlock()
	list := make([]*trc.TRC, 0, len(s.maxTrcMap))
	for isd, ver := range s.maxTrcMap {
		list = append(list, s.trcMap[*trc.NewKey(isd, ver)])
	}
	return list
}
