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

package csconfig

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/as_conf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// IssuerReissTime is the default value for Conf.IssuerReissTime. It is the same
	// as the leaf certificate validity period in order to provide optimal coverage.
	IssuerReissTime = cert.DefaultLeafCertValidity * time.Second
	// ReissReqRate is the default interval between two consecutive reissue requests.
	ReissReqRate = 10 * time.Second
	// ReissueReqTimeout is the default timeout of a reissue request.
	ReissueReqTimeout = 5 * time.Second
	// SciondTimeout is the default timeout of attempting to connect to sciond.
	SciondTimeout = 20 * time.Second
	// SciondRetryInterval is the default time between sciond connect attempts.
	SciondRetryInterval = time.Second

	ErrorKeyConf   = "Unable to load KeyConf"
	ErrorCustomers = "Unable to load Customers"
)

type Conf struct {
	// LeafReissueTime is the time between starting reissue requests and leaf cert expiration.
	LeafReissueTime duration
	// IssuerReissueTime is the time between self issuing core cert and core cert expiration.
	IssuerReissueTime duration
	// ReissueRate is the interval between two consecutive reissue requests.
	ReissueRate duration
	// ReissueTimeout is the timeout for resissue request.
	ReissueTimeout duration
	// SciondPath is the sciond path. It defaults to sciond.DefaultSCIONDPath.
	SciondPath string
	// SciondTimeout is the timeout when trying to connect to sciond.
	SciondTimeout duration
	// SciondRetryInterval is the time between sciond connect attempts.
	SciondRetryInterval duration

	// Store is the trust store.
	Store *trust.Store
	// TrustDB is the trust DB.
	TrustDB *trustdb.DB
	// MasterKeys holds the local AS master keys.
	MasterKeys *as_conf.MasterKeys
	// keyConf contains the AS level keys used for signing and decrypting.
	keyConf *trust.KeyConf
	// keyConfLock guards KeyConf, CertVer and TRCVer.
	keyConfLock sync.RWMutex
	// Customers is a mapping from non-core ASes assigned to this core AS to their public
	// verifying key.
	Customers *Customers
	// signer is used to sign ctrl payloads.
	signer ctrl.Signer
	// signerLock guards signer.
	signerLock sync.RWMutex
	// verifier is used to verify ctrl payloads.
	verifier ctrl.SigVerifier
	// verifierLock guards verifier.
	verifierLock sync.RWMutex
	// RequestID is used to generate unique request IDs for the messenger
	RequestID messenger.Counter
}

// Init sets the uninitialized fields and loads the keys.
func (c *Conf) Init(confDir string, isCore bool) error {
	c.initDefaults()
	if c.ReissueRate.Duration <= c.ReissueTimeout.Duration {
		return common.NewBasicError("Reissue rate must not be smaller than timeout", nil,
			"rate", c.ReissueRate.Duration, "timeout", c.ReissueTimeout.Duration)
	}
	if c.LeafReissueTime.Duration == 0 {
		if err := c.loadLeafReissTime(confDir); err != nil {
			return err
		}
	}
	if err := c.loadMasterKeys(confDir); err != nil {
		return err
	}
	if err := c.loadKeyConf(confDir, isCore); err != nil {
		return err
	}
	if isCore {
		var err error
		if c.Customers, err = c.LoadCustomers(confDir); err != nil {
			return common.NewBasicError(ErrorCustomers, err)
		}
	}
	return nil
}

func (c *Conf) initDefaults() {
	if c.SciondPath == "" {
		c.SciondPath = sciond.DefaultSCIONDPath
	}
	if c.IssuerReissueTime.Duration == 0 {
		c.IssuerReissueTime.Duration = IssuerReissTime
	}
	if c.ReissueRate.Duration == 0 {
		c.ReissueRate.Duration = ReissReqRate
	}
	if c.ReissueTimeout.Duration == 0 {
		c.ReissueTimeout.Duration = ReissueReqTimeout
	}
	if c.SciondRetryInterval.Duration == 0 {
		c.SciondRetryInterval.Duration = SciondRetryInterval
	}
	if c.SciondTimeout.Duration == 0 {
		c.SciondTimeout.Duration = SciondTimeout
	}
}

// loadMasterKeys loads the local AS master keys.
func (c *Conf) loadMasterKeys(confDir string) error {
	var err error
	c.MasterKeys, err = as_conf.LoadMasterKeys(filepath.Join(confDir, "keys"))
	if err != nil {
		return common.NewBasicError("Unable to load master keys", err)
	}
	return nil
}

// loadKeyConf loads the key configuration.
func (c *Conf) loadKeyConf(confDir string, isCore bool) error {
	var err error
	c.keyConf, err = trust.LoadKeyConf(filepath.Join(confDir, "keys"), isCore, isCore, false)
	if err != nil {
		return common.NewBasicError(ErrorKeyConf, err)
	}
	return nil
}

// loadLeafReissTime loads the as conf and sets the LeafReissTime to the PathSegmentTTL
// to provide optimal coverage.
func (c *Conf) loadLeafReissTime(confDir string) error {
	if err := as_conf.Load(filepath.Join(confDir, as_conf.CfgName)); err != nil {
		return err
	}
	c.LeafReissueTime.Duration = time.Duration(as_conf.CurrConf.PathSegmentTTL) * time.Second
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

var _ (toml.TextUnmarshaler) = (*duration)(nil)

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = util.ParseDuration(string(text))
	return err
}
