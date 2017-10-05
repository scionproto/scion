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
	"sync"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/crypto"
)

// keyTRC is the key type for trcMap.
type keyTRC struct {
	isd int
	ver int
}

// keyChain is the key type for chainMap.
type keyChain struct {
	ia  addr.ISD_AS
	ver int
}

const CertDir string = "certs"

type TrustStore struct {
	// dir is the configuration directory.
	dir string
	// certDir is the directory to cache TRCs and certs in.
	cacheDir string
	// eName is the element name, used to generate cache file names.
	eName string
	// chainMap is a mapping form (ISD-AS, version) to certificate chain
	chainMap map[keyChain]*crypto.CertificateChain
	// maxChainMap is a mapping from (ISD-AS) to max version.
	maxChainMap map[addr.ISD_AS]int
	// chainLock guards chainMap and maxChainMap.
	chainLock sync.RWMutex
}

func NewTrustStore(confDir, cacheDir, eName string) (*TrustStore, error) {
	dir := filepath.Join(confDir, CertDir)
	t := &TrustStore{dir: dir, cacheDir: cacheDir, eName: eName,
		chainMap:    make(map[keyChain]*crypto.CertificateChain),
		maxChainMap: make(map[addr.ISD_AS]int)}
	t.initChains()
	return t, nil
}

// initChains loads the certificate chain files from dir and cacheDir and populates chainMap
// as well as maxChainMap.
func (t *TrustStore) initChains() error {
	files, err := filepath.Glob(fmt.Sprintf("%s/*.crt", t.dir))
	if err != nil {
		return err
	}
	cachedFiles, err := filepath.Glob(fmt.Sprintf("%s/%s*.crt", t.cacheDir, t.eName))
	if err != nil {
		return err
	}

	for _, file := range append(files, cachedFiles...) {
		// FIXME(roosd): do not abort, but log errors
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}
		chain, err := crypto.CertificateChainFromRaw(raw, false)
		if err != nil {
			return err
		}
		if err = t.AddChain(chain, false); err != nil {
			return err
		}
	}
	return nil
}

// AddChain adds a trusted certificate chain to the store. If write is true, the TRC is written
// to the filesystem.
func (t *TrustStore) AddChain(chain *crypto.CertificateChain, write bool) error {
	ia, ver, err := chain.Leave.IsdAsVer()
	if err != nil {
		return err
	}
	key := keyChain{ia: *ia, ver: ver}
	t.chainLock.Lock()
	t.chainMap[key] = chain
	v, ok := t.maxChainMap[*ia]
	if ver > v || !ok {
		t.maxChainMap[*ia] = ver
		ok = false
	}
	t.chainLock.Unlock()
	if write && !ok {
		j, err := json.MarshalIndent(chain, "", "    ")
		if err != nil {
			return err
		}
		name := fmt.Sprintf("%s-ISD%d-AS%d-V%d.crt", t.eName, ia.I, ia.A, ver)
		ioutil.WriteFile(filepath.Join(t.cacheDir, name), j, 0644)
	}
	return nil
}

// GetChain returns the certificate chain for the specified values or nil, if it is not present.
func (t *TrustStore) GetChain(ia *addr.ISD_AS, ver int) *crypto.CertificateChain {
	t.chainLock.RLock()
	chain := t.chainMap[keyChain{*ia, ver}]
	t.chainLock.RUnlock()
	return chain
}

// GetMaxChain the certificate chain with the highest version for the specified ISD-AS.
func (t *TrustStore) GetMaxChain(ia *addr.ISD_AS) *crypto.CertificateChain {
	t.chainLock.RLock()
	var chain *crypto.CertificateChain
	ver, ok := t.maxChainMap[*ia]
	if ok {
		chain = t.chainMap[keyChain{*ia, ver}]
	}
	t.chainLock.RUnlock()
	return chain
}
