// Copyright 2018 ETH Zurich
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

package conf

import (
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/trust"
)

const (
	ErrorAddr      = "Unable to load addresses"
	ErrorKeyConf   = "Unable to load KeyConf"
	ErrorConfNil   = "Unable to reload conf from nil value"
	ErrorStore     = "Unable to load TrustStore"
	ErrorTopo      = "Unable to load topology"
	ErrorTrustDB   = "Unable to load trust DB"
	ErrorCustomers = "Unable to load Customers"
)

type Conf struct {
	// ID is the element ID.
	ID string
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo *topology.Topo
	// BindAddr is the local bind address.
	BindAddr *snet.Addr
	// PublicAddr is the public address.
	PublicAddr *snet.Addr
	// Store is the trust store.
	Store *trust.Store
	// TrustDB is the trust DB.
	TrustDB *trustdb.DB
	// keyConf contains the AS level keys used for signing and decrypting.
	keyConf *trust.KeyConf
	// keyConfLock guards KeyConf, CertVer and TRCVer.
	keyConfLock sync.RWMutex
	// Customers is a mapping from non-core ASes assigned to this core AS to their public
	// verifying key.
	Customers *Customers
	// CacheDir is the cache directory.
	CacheDir string
	// ConfDir is the configuration directory.
	ConfDir string
	// StateDir is the state directory.
	StateDir string
	// signer is used to sign ctrl payloads.
	signer ctrl.Signer
	// signerLock guards signer.
	signerLock sync.RWMutex
	// verifier is used to verify ctrl payloads.
	verifier ctrl.SigVerifier
	// verifierLock guards verifier.
	verifierLock sync.RWMutex
}

// Load initializes the configuration by loading it from confDir.
func Load(id string, confDir string, cacheDir string, stateDir string) (*Conf, error) {
	c := &Conf{
		ID:       id,
		ConfDir:  confDir,
		CacheDir: cacheDir,
		StateDir: stateDir,
	}
	if err := c.loadTopo(); err != nil {
		return nil, err
	}
	if err := c.loadStore(); err != nil {
		return nil, err
	}
	if err := c.loadTrustDB(); err != nil {
		return nil, err
	}
	if err := c.loadKeyConf(); err != nil {
		return nil, err
	}
	if c.Topo.Core {
		var err error
		if c.Customers, err = c.LoadCustomers(); err != nil {
			return nil, common.NewBasicError(ErrorCustomers, err)
		}
	}
	return c, nil
}

// ReloadConf loads a new configuration based on the old one.
func ReloadConf(oldConf *Conf) (*Conf, error) {
	if oldConf == nil {
		return nil, common.NewBasicError(ErrorConfNil, nil)
	}
	// FIXME(roosd): Changing keys for customers outside of the process on-disk
	// requires a restart of the certificate server in order to be visible.
	c := &Conf{
		ID:        oldConf.ID,
		TrustDB:   oldConf.TrustDB,
		Customers: oldConf.Customers,
		ConfDir:   oldConf.ConfDir,
		CacheDir:  oldConf.CacheDir,
		StateDir:  oldConf.StateDir,
	}
	if err := c.loadTopo(); err != nil {
		return nil, err
	}
	if err := c.loadStore(); err != nil {
		return nil, err
	}
	if err := c.loadKeyConf(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadTopo loads the topology information.
func (c *Conf) loadTopo() (err error) {
	path := filepath.Join(c.ConfDir, topology.CfgName)
	if c.Topo, err = topology.LoadFromFile(path); err != nil {
		return common.NewBasicError(ErrorTopo, err)
	}
	// load public and bind address
	topoAddr, ok := c.Topo.CS[c.ID]
	if !ok {
		return common.NewBasicError(ErrorAddr, nil, "err", "Element ID not found", "id", c.ID)
	}
	publicInfo := topoAddr.PublicAddrInfo(c.Topo.Overlay)
	c.PublicAddr = &snet.Addr{IA: c.Topo.ISD_AS, Host: addr.HostFromIP(publicInfo.IP),
		L4Port: uint16(publicInfo.L4Port)}
	bindInfo := topoAddr.BindAddrInfo(c.Topo.Overlay)
	tmpBind := &snet.Addr{IA: c.Topo.ISD_AS, Host: addr.HostFromIP(bindInfo.IP),
		L4Port: uint16(bindInfo.L4Port)}
	if !tmpBind.EqAddr(c.PublicAddr) {
		c.BindAddr = tmpBind
	}
	return nil
}

// loadStore loads the trust store.
func (c *Conf) loadStore() (err error) {
	c.Store, err = trust.NewStore(filepath.Join(c.ConfDir, "certs"), c.CacheDir, c.ID)
	if err != nil {
		return common.NewBasicError(ErrorStore, err)
	}
	return nil
}

// loadTrustDB loads the trustdb.
func (c *Conf) loadTrustDB() (err error) {
	if c.TrustDB, err = trustdb.New(filepath.Join(c.StateDir, trustdb.Path)); err != nil {
		return common.NewBasicError(ErrorTrustDB, err)
	}
	return nil
}

// loadKeyConf loads the key configuration.
func (c *Conf) loadKeyConf() (err error) {
	c.keyConf, err = trust.LoadKeyConf(filepath.Join(c.ConfDir, "keys"), c.Topo.Core,
		c.Topo.Core, false)
	if err != nil {
		return common.NewBasicError(ErrorKeyConf, err)
	}
	return nil
}

// GetSigningKey returns the signing key of the current key configuration.
func (c *Conf) GetSigningKey() common.RawBytes {
	c.keyConfLock.RLock()
	defer c.keyConfLock.RUnlock()
	return c.keyConf.SignKey
}

// GetDecryptKey returns the decryption key of the current key configuration.
func (c *Conf) GetDecryptKey() common.RawBytes {
	c.keyConfLock.RLock()
	defer c.keyConfLock.RUnlock()
	return c.keyConf.DecryptKey
}

// GetOnRootKey returns the online root key of the current key configuration.
func (c *Conf) GetOnRootKey() common.RawBytes {
	c.keyConfLock.RLock()
	defer c.keyConfLock.RUnlock()
	return c.keyConf.OnRootKey
}

// GetSigner returns the signer of the current configuration.
func (c *Conf) GetSigner() ctrl.Signer {
	c.signerLock.RLock()
	defer c.signerLock.RUnlock()
	return c.signer
}

// SetSigner sets the signer of the current configuration.
func (c *Conf) SetSigner(signer ctrl.Signer) {
	c.signerLock.Lock()
	defer c.signerLock.Unlock()
	c.signer = signer
}

// GetVerifier returns the verifier of the current configuration.
func (c *Conf) GetVerifier() ctrl.SigVerifier {
	c.verifierLock.RLock()
	defer c.verifierLock.RUnlock()
	return c.verifier
}

// SetVerifier sets the verifier of the current configuration.
func (c *Conf) SetVerifier(verifier ctrl.SigVerifier) {
	c.verifierLock.Lock()
	defer c.verifierLock.Unlock()
	c.verifier = verifier
}

var conf atomic.Value

// Get returns a pointer to the current configuration.
func Get() *Conf {
	c := conf.Load()
	if c != nil {
		return c.(*Conf)
	}
	return nil
}

// Set updates the current configuration.
func Set(c *Conf) {
	conf.Store(c)
}
