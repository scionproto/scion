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
	"bytes"
	"path/filepath"
	"sync"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/trust"
)

const (
	ErrorTopo      = "Unable to load topology"
	ErrorAddr      = "Unable to load addresses"
	ErrorKeyConf   = "Unable to load KeyConf"
	ErrorStore     = "Unable to load TrustStore"
	ErrorFatal     = "Fatal error"
	InvalidKeyConf = "Invalid KeyConf"
)

type Conf struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo *topology.Topo
	// BindAddr is the local bind address.
	BindAddr *snet.Addr
	// PublicAddr is the public address.
	PublicAddr *snet.Addr
	// Store is the trust store.
	Store *trust.Store
	// keyConf contains the AS level keys used for signing and decrypting.
	keyConf *trust.KeyConf
	// keyConfLock guards KeyConf, CertVer and TRCVer.
	keyConfLock sync.RWMutex
	// Dir is the configuration directory.
	Dir string
}

// Load initializes the configuration by loading it from confDir.
func Load(id string, confDir string) (*Conf, error) {
	var err error
	conf := &Conf{Dir: confDir}
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
	// load trust store
	conf.Store, err = trust.NewStore(filepath.Join(confDir, "certs"), confDir, id)
	if err != nil {
		return nil, common.NewBasicError(ErrorStore, err)
	}
	if conf.keyConf, err = conf.loadKeyConf(); err != nil {
		return nil, common.NewBasicError(ErrorKeyConf, err)
	}

	if err = conf.verifyKeyConf(conf.keyConf); err != nil {
		return nil, common.NewBasicError(ErrorKeyConf, err)
	}
	return conf, nil
}

// Reload reloads trust store and and key configuration. KeyConfig is only replaced, if the loaded
// keys are usable in combination with the active TRC and certificate chain. Otherwise an error is
// returned. If the error message is ErrorFatal, the old keyConfig is not usable either.
func (c *Conf) Reload() error {
	if err := c.Store.Reload(); err != nil {
		return common.NewBasicError(ErrorStore, err)
	}
	c.keyConfLock.Lock()
	defer c.keyConfLock.Unlock()
	keyConf, err := c.loadKeyConf()
	if err == nil {
		// Check if new key config is usable with the current TRC and certificate chain
		if err = c.verifyKeyConf(keyConf); err == nil {
			c.keyConf = keyConf
			return nil
		}
	}
	// Check that old key config is usable with the current (possible freshly loaded)
	// TRC and certificate chain
	existingErr := c.verifyKeyConf(c.keyConf)
	if existingErr == nil {
		return err
	}
	return common.NewBasicError(ErrorFatal, err, "existingErr", common.FmtError(existingErr))
}

// loadKeyConf loads key configuration.
func (c *Conf) loadKeyConf() (*trust.KeyConf, error) {
	// Certificate server does not need offline root key during normal operations
	return trust.LoadKeyConf(filepath.Join(c.Dir, "keys"), c.Topo.Core, false)
}

// verifyKeyConf verifies that the key configuration is usable in combination with the active TRC
// and certificate chain.
func (c *Conf) verifyKeyConf(keyConf *trust.KeyConf) error {
	chain := c.Store.GetNewestChain(c.PublicAddr.IA)
	if chain == nil {
		return common.NewBasicError(ErrorFatal, nil, "err", "No certificate chain")
	}
	// Check that the public key config matches the public key in the certificate chain
	verKey := common.RawBytes(ed25519.PrivateKey(keyConf.SignKey).Public().(ed25519.PublicKey))
	if !bytes.Equal(chain.Leaf.SubjectSignKey, verKey) {
		// FIXME(roosd): Add check for SubjectEncKey
		return common.NewBasicError(InvalidKeyConf, nil, "err", "Certificate "+
			"chain does not authenticate keys", "chain", chain, "verKey", verKey)
	}
	// Check that the current certificate chain is verifiable with current TRC (or grace TRC)
	if err := c.verifyCC(chain); err != nil {
		return err
	}
	// Check root keys are authenticated by current TRC (or grace TRC)
	if c.Topo.Core {
		// get current TRC (and possibly grace TRC)
		t, graceT, err := c.getActiveTRC()
		if err != nil {
			return common.NewBasicError(ErrorFatal, err)
		}
		// Check if root keys authenticated by active TRC
		if err = c.verifyRootKeys(keyConf, t); err != nil {
			// Check if root keys authenticated by grace TRC
			if graceErr := c.verifyRootKeys(keyConf, graceT); graceErr != nil {
				return common.NewBasicError(ErrorFatal, err, "graceErr",
					common.FmtError(graceErr))
			}
			log.Warn("Current root keys rely on TRC in grace period", "TRC", graceT)
		}
	}
	return nil
}

// verifyCC verifies that the provided certificate chain is verifiable with the current TRCs.
func (c *Conf) verifyCC(chain *cert.Chain) error {
	t, graceT, err := c.getActiveTRC()
	if err != nil {
		return common.NewBasicError(ErrorFatal, err)
	}
	if t != nil && chain.Verify(c.PublicAddr.IA, t) == nil {
		return nil
	}
	if graceT != nil && chain.Verify(c.PublicAddr.IA, graceT) == nil {
		log.Warn("Current certificate chain relies on TRC in grace period", "TRC", graceT)
		return nil
	}
	return common.NewBasicError(InvalidKeyConf, nil, "Certificate chain not verifiable",
		"chain", chain, "trc", t, "graceTRC", graceT)
}

// verifyRootKeys verifies that the root keys in keyConf are authenticated by the provided TRC.
func (c *Conf) verifyRootKeys(keyConf *trust.KeyConf, t *trc.TRC) error {
	if t == nil {
		return common.NewBasicError("No TRC provided to verify root keys", nil)
	}
	// Check that this AS is part of the core ASes
	coreEntry := t.CoreASes[*c.PublicAddr.IA]
	if coreEntry == nil {
		return common.NewBasicError("Not a core AS", nil, "IA", c.PublicAddr.IA, "TRC", t)
	}
	// Check that online key is authenticated by TRC
	onPubKey := ed25519.PrivateKey(keyConf.OnRootKey).Public().(ed25519.PublicKey)
	if !bytes.Equal(coreEntry.OnlineKey, onPubKey) {
		return common.NewBasicError("Online key does not match", nil, "TRC", t)
	}
	// Offline key is not available during normal operations
	if keyConf.OffRootKey == nil {
		return nil
	}
	// Check that offline key is authenticated by TRC
	offPubKey := ed25519.PrivateKey(keyConf.OffRootKey).Public().(ed25519.PublicKey)
	if !bytes.Equal(coreEntry.OfflineKey, offPubKey) {
		return common.NewBasicError("Offline key does not match", nil, "TRC", t)
	}
	return nil
}

// getActiveTRC returns active TRCs if they exist or an error. The first return value is the
// active TRC. The second return value is the grace TRC if the grace period has not passed yet.
func (c *Conf) getActiveTRC() (*trc.TRC, *trc.TRC, error) {
	t := c.Store.GetNewestTRC(uint16(c.PublicAddr.IA.I))
	if t == nil {
		return nil, nil, common.NewBasicError("No TRC for own ISD", nil)
	}
	// This loop iterates through all TRC versions (starting from the newest TRC) and find the
	// latest TRC which is not early usage
	for ver := t.Version - 1; ver >= 0; ver-- {
		// Check if creation time is in the future. GetErrorMsg(nil) returns empty string
		if err := t.CheckActive(t); common.GetErrorMsg(err) != trc.EarlyUsage {
			break
		}
		// A valid trust store must posses the preceding TRC
		if t = c.Store.GetTRC(uint16(c.PublicAddr.IA.I), ver-1); t == nil {
			return nil, nil, common.NewBasicError("Missing TRC", nil, "ver", ver)
		}
	}
	// Check that the TRC is active
	if err := t.CheckActive(t); err != nil {
		return nil, nil, common.NewBasicError("No active TRC", nil)
	}
	// Also return the grace TRC, if it is active
	if t.Version > 0 {
		graceT := c.Store.GetTRC(uint16(c.PublicAddr.IA.I), t.Version-1)
		if err := graceT.CheckActive(t); err != nil {
			return t, nil, nil
		}
		return t, graceT, nil
	}
	return t, nil, nil
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
