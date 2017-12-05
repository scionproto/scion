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
)

// Store handles storage and management of trust objects (certificate chains)
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
	maxChainMap map[addr.ISD_AS]uint64
	// chainLock guards chainMap and maxChainMap.
	chainLock sync.RWMutex
}

func NewStore(certDir, cacheDir, eName string) (*Store, error) {
	s := &Store{certDir: certDir, cacheDir: cacheDir, eName: eName,
		chainMap:    make(map[cert.Key]*cert.Chain),
		maxChainMap: make(map[addr.ISD_AS]uint64)}
	s.initChains()
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

// AddChain adds a trusted certificate chain to the store. If write is true, the certificate chain
// is written to the filesystem (in case it does not already exist).
func (s *Store) AddChain(chain *cert.Chain, write bool) error {
	ia, ver := chain.IAVer()
	key := *chain.Key()
	s.chainLock.Lock()
	if _, ok := s.chainMap[key]; !ok {
		s.chainMap[key] = chain
		if v, ok := s.maxChainMap[*ia]; !ok || ver > v {
			s.maxChainMap[*ia] = ver
		}
	}
	s.chainLock.Unlock()
	if write {
		return s.writeChain(chain)
	}
	return nil
}

// writeChain writes certificate chain to the store, if it does not already exist.
func (s *Store) writeChain(chain *cert.Chain) error {
	ia, ver := chain.IAVer()
	name := fmt.Sprintf("%s-ISD%d-AS%d-V%d.crt", s.eName, ia.I, ia.A, ver)
	path := filepath.Join(s.cacheDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		j, err := chain.JSON(true)
		if err != nil {
			return err
		}
		if err = ioutil.WriteFile(path, j, 0644); err != nil {
			return err
		}
	}
	return nil
}

// GetChain returns the certificate chain for the specified values or nil, if it is not present.
func (s *Store) GetChain(ia *addr.ISD_AS, ver uint64) *cert.Chain {
	s.chainLock.RLock()
	defer s.chainLock.RUnlock()
	return s.chainMap[*cert.NewKey(ia, ver)]
}

// GetMaxChain the certificate chain with the highest version for the specified ISD-AS.
func (s *Store) GetNewestChain(ia *addr.ISD_AS) *cert.Chain {
	s.chainLock.RLock()
	defer s.chainLock.RUnlock()
	var chain *cert.Chain
	ver, ok := s.maxChainMap[*ia]
	if ok {
		chain = s.chainMap[*cert.NewKey(ia, ver)]
	}
	return chain
}
