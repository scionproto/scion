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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/crypto/cert"
)

type Store struct {
	// certDir is the certificate directory.
	certDir string
	// certDir is the directory to cache TRCs and certs in.
	cacheDir string
	// eName is the element name, used to generate cache file names.
	eName string
	// chainMap is a mapping form (ISD-AS, version) to certificate chain
	chainMap map[cert.Key]*cert.Chain
	// maxChainMap is a mapping from (ISD-AS) to max version.
	maxChainMap map[addr.ISD_AS]int
	// chainLock guards chainMap and maxChainMap.
	chainLock sync.RWMutex
}

func NewStore(certDir, cacheDir, eName string) (*Store, error) {
	s := &Store{certDir: certDir, cacheDir: cacheDir, eName: eName,
		chainMap:    make(map[cert.Key]*cert.Chain),
		maxChainMap: make(map[addr.ISD_AS]int)}
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

// AddChain adds a trusted certificate chain to the store. If write is true, the TRC is written
// to the filesystem.
func (s *Store) AddChain(chain *cert.Chain, write bool) error {
	ia, ver := chain.IAVer()
	s.chainLock.Lock()
	s.chainMap[*chain.Key()] = chain
	v, ok := s.maxChainMap[*ia]
	if !ok || ver > v {
		s.maxChainMap[*ia] = ver
		ok = false
	}
	s.chainLock.Unlock()
	if write && !ok {
		j, err := json.MarshalIndent(chain, "", strings.Repeat(" ", 4))
		if err != nil {
			return err
		}
		name := fmt.Sprintf("%s-ISD%d-AS%d-V%d.crt", s.eName, ia.I, ia.A, ver)
		if err = ioutil.WriteFile(filepath.Join(s.cacheDir, name), j, 0644); err != nil {
			return err
		}
	}
	return nil
}

// GetChain returns the certificate chain for the specified values or nil, if it is not present.
func (s *Store) GetChain(ia *addr.ISD_AS, ver int) *cert.Chain {
	s.chainLock.RLock()
	defer s.chainLock.RUnlock()
	chain := s.chainMap[cert.Key{IA: *ia, Ver: ver}]
	return chain
}

// GetMaxChain the certificate chain with the highest version for the specified ISD-AS.
func (s *Store) GetNewestChain(ia *addr.ISD_AS) *cert.Chain {
	s.chainLock.RLock()
	defer s.chainLock.RUnlock()
	var chain *cert.Chain
	ver, ok := s.maxChainMap[*ia]
	if ok {
		chain = s.chainMap[cert.Key{IA: *ia, Ver: ver}]
	}
	return chain
}
