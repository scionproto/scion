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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/trust"
)

const (
	ErrorAddr      = "Unable to load addresses"
	ErrorKeyConf   = "Unable to load KeyConf"
	ErrorTopo      = "Unable to load topology"
	ErrorCustomers = "Unable to load Customers"
)

type Conf struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo *topology.Topo
	// BindAddr is the local bind address.
	BindAddr *snet.Addr
	// PublicAddr is the public address.
	PublicAddr *snet.Addr
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
	var err error
	conf := &Conf{
		ConfDir:  confDir,
		CacheDir: cacheDir,
		StateDir: stateDir,
	}
	// load topology
	path := filepath.Join(confDir, topology.CfgName)
	if conf.Topo, err = topology.LoadFromFile(path); err != nil {
		return nil, common.NewBasicError(ErrorTopo, err)
	}
	// load public and bind address
	topoAddr, ok := conf.Topo.CS[id]
	if !ok {
		return nil, common.NewBasicError(ErrorAddr, nil, "err", "Element ID not found",
			"id", id)
	}
	publicInfo := topoAddr.PublicAddrInfo(conf.Topo.Overlay)
	conf.PublicAddr = &snet.Addr{IA: conf.Topo.ISD_AS, Host: addr.HostFromIP(publicInfo.IP),
		L4Port: uint16(publicInfo.L4Port)}
	bindInfo := topoAddr.BindAddrInfo(conf.Topo.Overlay)
	tmpBind := &snet.Addr{IA: conf.Topo.ISD_AS, Host: addr.HostFromIP(bindInfo.IP),
		L4Port: uint16(bindInfo.L4Port)}
	if !tmpBind.EqAddr(conf.PublicAddr) {
		conf.BindAddr = tmpBind
	}
	// load key configuration
	if conf.keyConf, err = conf.loadKeyConf(); err != nil {
		return nil, common.NewBasicError(ErrorKeyConf, err)
	}
	if conf.Topo.Core {
		// load customers
		if conf.Customers, err = conf.LoadCustomers(); err != nil {
			return nil, common.NewBasicError(ErrorCustomers, err)
		}
	}
	return conf, nil
}

// loadKeyConf loads key configuration.
func (c *Conf) loadKeyConf() (*trust.KeyConf, error) {
	return trust.LoadKeyConf(filepath.Join(c.ConfDir, "keys"), c.Topo.Core,
		c.Topo.Core, false)
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
