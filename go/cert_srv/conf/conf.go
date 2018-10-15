// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/go/lib/as_conf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	// IssuerReissTime is the default value for Conf.IssuerReissTime. It is the same
	// as the leaf certificate validity period in order to provide optimal coverage.
	IssuerReissTime = cert.DefaultLeafCertValidity * time.Second
	// ReissReqRate is the default interval between two consecutive reissue requests.
	ReissReqRate = 10 * time.Second

	ErrorAddr      = "Unable to load addresses"
	ErrorIssCert   = "Unable to load issuer certificate"
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
	// ASConf is the local AS configuration.
	ASConf *as_conf.ASConf
	// MasterKeys holds the local AS master keys.
	MasterKeys *as_conf.MasterKeys
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
	// LeafReissTime is the time between starting reissue requests and leaf cert expiration.
	LeafReissTime time.Duration
	// IssuerReissTime is the time between self issuing core cert and core cert expiration.
	IssuerReissTime time.Duration
	// ReissRate is the interval between two consecutive reissue requests.
	ReissRate time.Duration
}

// Load initializes the configuration by loading it from confDir.
func Load(id string, confDir string, stateDir string) (*Conf, error) {
	c := &Conf{
		ID:              id,
		ConfDir:         confDir,
		StateDir:        stateDir,
		IssuerReissTime: IssuerReissTime,
		ReissRate:       ReissReqRate,
	}
	if err := c.loadLeafReissTime(); err != nil {
		return nil, err
	}
	if err := c.loadTopo(); err != nil {
		return nil, err
	}
	if err := c.loadAsConf(); err != nil {
		return nil, err
	}
	if err := c.loadMasterKeys(); err != nil {
		return nil, err
	}
	if err := c.loadTrustDB(); err != nil {
		return nil, err
	}
	if err := c.loadStore(); err != nil {
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
		if err = c.checkIssCert(); err != nil {
			return nil, err
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
		ID:              oldConf.ID,
		TrustDB:         oldConf.TrustDB,
		Customers:       oldConf.Customers,
		ConfDir:         oldConf.ConfDir,
		StateDir:        oldConf.StateDir,
		IssuerReissTime: IssuerReissTime,
		ReissRate:       ReissReqRate,
	}
	if err := c.loadLeafReissTime(); err != nil {
		return nil, err
	}
	if err := c.loadTopo(); err != nil {
		return nil, err
	}
	if err := c.loadAsConf(); err != nil {
		return nil, err
	}
	if err := c.loadMasterKeys(); err != nil {
		return nil, err
	}
	if err := c.loadStore(); err != nil {
		return nil, err
	}
	if err := c.loadKeyConf(); err != nil {
		return nil, err
	}
	if c.Topo.Core {
		if err := c.checkIssCert(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// loadTopo loads the topology information.
func (c *Conf) loadTopo() error {
	var err error
	path := filepath.Join(c.ConfDir, topology.CfgName)
	if c.Topo, err = topology.LoadFromFile(path); err != nil {
		return common.NewBasicError(ErrorTopo, err)
	}
	// load public and bind address
	topoAddr, ok := c.Topo.CS[c.ID]
	if !ok {
		return common.NewBasicError(ErrorAddr, nil, "err", "Element ID not found", "id", c.ID)
	}
	pub := topoAddr.PublicAddr(c.Topo.Overlay)
	c.PublicAddr = &snet.Addr{IA: c.Topo.ISD_AS, Host: pub}
	bind := topoAddr.BindAddr(c.Topo.Overlay)
	if bind != nil {
		c.BindAddr = &snet.Addr{IA: c.Topo.ISD_AS, Host: bind}
	}
	return nil
}

// loadASConf loads the local AS configuration.
func (c *Conf) loadAsConf() error {
	if err := as_conf.Load(filepath.Join(c.ConfDir, as_conf.CfgName)); err != nil {
		return common.NewBasicError("Unable to load ASConf", err)
	}
	c.ASConf = as_conf.CurrConf
	return nil
}

// loadMasterKeys loads the local AS master keys.
func (c *Conf) loadMasterKeys() error {
	var err error
	c.MasterKeys, err = as_conf.LoadMasterKeys(filepath.Join(c.ConfDir, "keys"))
	if err != nil {
		return common.NewBasicError("Unable to load master keys", err)
	}
	return nil
}

// loadStore loads the trust store.
func (c *Conf) loadStore() error {
	var err error
	c.Store, err = trust.NewStore(
		c.TrustDB,
		c.Topo.ISD_AS,
		scrypto.RandUint64(),
		&trust.Config{
			MustHaveLocalChain: true,
		},
		log.Root(),
	)
	if err != nil {
		return common.NewBasicError(ErrorStore, err)
	}
	if err := c.Store.LoadAuthoritativeTRC(filepath.Join(c.ConfDir, "certs")); err != nil {
		return err
	}
	if err := c.Store.LoadAuthoritativeChain(filepath.Join(c.ConfDir, "certs")); err != nil {
		return err
	}
	return nil
}

// loadTrustDB loads the trustdb.
func (c *Conf) loadTrustDB() error {
	var err error
	if c.TrustDB, err = trustdb.New(filepath.Join(c.StateDir, trustdb.Path)); err != nil {
		return common.NewBasicError(ErrorTrustDB, err)
	}
	return nil
}

// loadKeyConf loads the key configuration.
func (c *Conf) loadKeyConf() error {
	var err error
	c.keyConf, err = trust.LoadKeyConf(filepath.Join(c.ConfDir, "keys"), c.Topo.Core,
		c.Topo.Core, false)
	if err != nil {
		return common.NewBasicError(ErrorKeyConf, err)
	}
	return nil
}

// loadLeafReissTime loads the as conf and sets the LeafReissTime to the PathSegmentTTL
// to provide optimal coverage.
func (c *Conf) loadLeafReissTime() error {
	if err := as_conf.Load(filepath.Join(c.ConfDir, as_conf.CfgName)); err != nil {
		return err
	}
	c.LeafReissTime = time.Duration(as_conf.CurrConf.PathSegmentTTL) * time.Second
	return nil
}

// checkIssCert checks that the trust store contains the issuer certificate.
func (c *Conf) checkIssCert() error {
	chain, err := c.Store.GetValidChain(context.Background(), c.PublicAddr.IA, nil)
	if err != nil {
		return err
	}
	if chain == nil {
		return common.NewBasicError(ErrorIssCert, nil, "err", "No certificate chain present")
	}
	return nil
}

// GetSigningKey returns the signing key of the current key configuration.
func (c *Conf) GetSigningKey() common.RawBytes {
	c.keyConfLock.RLock()
	defer c.keyConfLock.RUnlock()
	return c.keyConf.SignKey
}

// GetIssSigningKey returns the issuer signing key of the current key configuration.
func (c *Conf) GetIssSigningKey() common.RawBytes {
	c.keyConfLock.RLock()
	defer c.keyConfLock.RUnlock()
	return c.keyConf.IssSigKey
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
