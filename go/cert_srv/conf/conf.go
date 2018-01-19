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
	// TRCVer is the TRC version that is currently used.
	TRCVer uint64
	// CertVer is the certificate chain version that is currently used.
	CertVer uint64
	// KeyConf contains the AS level keys used for signing and decrypting.
	KeyConf *trust.KeyConf
	// KeyConfLock guards KeyConf, CertVer and TRCVer.
	KeyConfLock sync.RWMutex
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
	if conf.KeyConf, err = conf.loadKeyConf(); err != nil {
		return nil, common.NewBasicError(ErrorKeyConf, err)
	}

	if conf.CertVer, conf.TRCVer, err = conf.checkKeyConf(conf.KeyConf); err != nil {
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
	c.KeyConfLock.Lock()
	defer c.KeyConfLock.Unlock()
	keyConf, err := c.loadKeyConf()
	if err == nil {
		var certVer, trcVer uint64
		if certVer, trcVer, err = c.checkKeyConf(keyConf); err == nil {
			c.KeyConf = keyConf
			c.CertVer = certVer
			c.TRCVer = trcVer
			return nil
		}
	}
	certVer, trcVer, errO := c.checkKeyConf(c.KeyConf)
	if errO == nil {
		c.CertVer = certVer
		c.TRCVer = trcVer
		return err
	}
	return common.NewBasicError(ErrorFatal, err, "errExistingKeyConf", common.FmtError(errO))
}

// loadKeyConf loads key configuration.
func (c *Conf) loadKeyConf() (*trust.KeyConf, error) {
	return trust.LoadKeyConf(filepath.Join(c.Dir, "keys"), c.Topo.Core)
}

// checkKeyConf checks if key configuration is usable in combination with the active TRC and
// certificate chain and returns the associated versions.
func (c *Conf) checkKeyConf(keyConf *trust.KeyConf) (uint64, uint64, error) {
	t, graceT, err := c.getTRC(keyConf)
	if err != nil {
		return 0, 0, err
	}
	chain, usedT, err := c.getChain(keyConf, t, graceT)
	if err != nil {
		return 0, 0, err
	}
	if usedT == graceT {
		log.Warn("KeyConf relys on TRC in grace period", "TRC", usedT)
	}
	return chain.Leaf.Version, usedT.Version, nil
}

// getTRC returns the TRCs which are usable with this keyConf or an error. The first return value
// is the active TRC. The second return value is the TRC still active in the grace period.
func (c *Conf) getTRC(keyConf *trust.KeyConf) (*trc.TRC, *trc.TRC, error) {
	t, graceT, err := c.getActiveTRC()
	if err != nil {
		return nil, nil, common.NewBasicError(ErrorFatal, err)
	}
	if !c.Topo.Core {
		return t, graceT, nil
	}
	onPubKey := ed25519.PrivateKey(keyConf.OnRootKey).Public().(ed25519.PublicKey)
	offPubKey := ed25519.PrivateKey(keyConf.OffRootKey).Public().(ed25519.PublicKey)
	if t != nil && (!bytes.Equal(t.CoreASes[*c.PublicAddr.IA].OfflineKey, offPubKey) ||
		!bytes.Equal(t.CoreASes[*c.PublicAddr.IA].OnlineKey, onPubKey)) {
		t = nil
	}
	if graceT != nil && (!bytes.Equal(graceT.CoreASes[*c.PublicAddr.IA].OfflineKey, offPubKey) ||
		!bytes.Equal(graceT.CoreASes[*c.PublicAddr.IA].OnlineKey, onPubKey)) {
		graceT = nil
	}
	if t == nil && graceT == nil {
		return nil, nil, common.NewBasicError(InvalidKeyConf, nil, "err", "No matching TRC")
	}
	return t, graceT, nil
}

// getActiveTRC returns active TRCs if they exist or an error. The first return value is the
// active TRC. The second return value is the TRC still active in the grace period.
func (c *Conf) getActiveTRC() (*trc.TRC, *trc.TRC, error) {
	t := c.Store.GetNewestTRC(uint16(c.PublicAddr.IA.I))
	if t == nil {
		return nil, nil, common.NewBasicError("No TRC for own ISD", nil)
	}
	for ver := t.Version - 1; ver >= 0; ver-- {
		if err := t.CheckActive(t); common.GetErrorMsg(err) != trc.EarlyUsage {
			break
		}
		if t = c.Store.GetTRC(uint16(c.PublicAddr.IA.I), ver-1); t == nil {
			return nil, nil, common.NewBasicError("Missing TRC", nil, "ver", ver)
		}
	}
	if err := t.CheckActive(t); err != nil {
		return nil, nil, common.NewBasicError("No active TRC", nil)
	}
	if t.Version > 0 {
		graceT := c.Store.GetTRC(uint16(c.PublicAddr.IA.I), t.Version-1)
		if err := graceT.CheckActive(t); err != nil {
			return t, nil, nil
		}
		return t, graceT, nil
	}
	return t, nil, nil
}

// getChain returns the newest certificate chain if it is verifiable and authenticates
// the keys in keyConf. Otherwise, an error is returned. The SubjectSignKey must match in the newest
// certificate. If this is not the case, the responsible core AS has a different verifying key in
// its mapping and no certificate reissuance requests will be accepted.
func (c *Conf) getChain(keyConf *trust.KeyConf, t, graceT *trc.TRC) (*cert.Chain, *trc.TRC, error) {
	chain := c.Store.GetNewestChain(c.PublicAddr.IA)
	if chain == nil {
		return nil, nil, common.NewBasicError(ErrorFatal, nil, "err", "No certificate chain")
	}
	verKey := common.RawBytes(ed25519.PrivateKey(keyConf.SignKey).Public().(ed25519.PublicKey))
	if !bytes.Equal(chain.Leaf.SubjectSignKey, verKey) {
		// FIXME(roosd): Add check for SubjectEncKey
		return nil, nil, common.NewBasicError(InvalidKeyConf, nil, "err", "Certificate "+
			"chain does not authenticate keys", "chain", chain, "verKey", verKey)
	}
	if t != nil && chain.Verify(c.PublicAddr.IA, t) == nil {
		return chain, t, nil
	}
	if graceT != nil && chain.Verify(c.PublicAddr.IA, graceT) == nil {
		return chain, graceT, nil
	}
	return nil, nil, common.NewBasicError(InvalidKeyConf, nil, "Certificate chain not "+
		"verifiable", "chain", chain, "trc", t, "graceTRC", graceT)
}
