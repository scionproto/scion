// Copyright 2018 Anapaya Systems
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

package config

import (
	"path/filepath"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/keyconf"
)

type State struct {
	// Store is the trust store.
	Store *trust.Store
	// TrustDB is the trust DB.
	TrustDB trustdb.TrustDB
	// keyConf contains the AS level keys.
	keyConf *keyconf.Conf
	// keyConfLock guards KeyConf.
	keyConfLock sync.RWMutex
	// signer is used to sign ctrl payloads.
	signer ctrl.Signer
	// signerLock guards signer.
	signerLock sync.RWMutex
	// verifier is used to verify ctrl payloads.
	verifier ctrl.SigVerifier
	// verifierLock guards verifier.
	verifierLock sync.RWMutex
}

func LoadState(confDir string, isCore bool, trustDB trustdb.TrustDB,
	trustStore *trust.Store) (*State, error) {

	s := &State{
		Store:   trustStore,
		TrustDB: trustDB,
	}
	if err := s.loadKeyConf(confDir, isCore); err != nil {
		return nil, err
	}
	return s, nil
}

// loadKeyConf loads the key configuration.
func (s *State) loadKeyConf(confDir string, isCore bool) error {
	var err error
	s.keyConf, err = keyconf.Load(filepath.Join(confDir, "keys"), isCore, isCore, false, true)
	if err != nil {
		return common.NewBasicError(ErrorKeyConf, err)
	}
	return nil
}

// GetSigningKey returns the signing key of the current key configuration.
func (s *State) GetSigningKey() common.RawBytes {
	s.keyConfLock.RLock()
	defer s.keyConfLock.RUnlock()
	return s.keyConf.SignKey
}

// GetIssSigningKey returns the issuer signing key of the current key configuration.
func (s *State) GetIssSigningKey() common.RawBytes {
	s.keyConfLock.RLock()
	defer s.keyConfLock.RUnlock()
	return s.keyConf.IssSigKey
}

// GetDecryptKey returns the decryption key of the current key configuration.
func (s *State) GetDecryptKey() common.RawBytes {
	s.keyConfLock.RLock()
	defer s.keyConfLock.RUnlock()
	return s.keyConf.DecryptKey
}

// GetOnRootKey returns the online root key of the current key configuration.
func (s *State) GetOnRootKey() common.RawBytes {
	s.keyConfLock.RLock()
	defer s.keyConfLock.RUnlock()
	return s.keyConf.OnRootKey
}

// GetSigner returns the signer of the current configuration.
func (s *State) GetSigner() ctrl.Signer {
	s.signerLock.RLock()
	defer s.signerLock.RUnlock()
	return s.signer
}

// SetSigner sets the signer of the current configuration.
func (s *State) SetSigner(signer ctrl.Signer) {
	s.signerLock.Lock()
	defer s.signerLock.Unlock()
	s.signer = signer
}

// GetVerifier returns the verifier of the current configuration.
func (s *State) GetVerifier() ctrl.SigVerifier {
	s.verifierLock.RLock()
	defer s.verifierLock.RUnlock()
	return s.verifier
}

// SetVerifier sets the verifier of the current configuration.
func (s *State) SetVerifier(verifier ctrl.SigVerifier) {
	s.verifierLock.Lock()
	defer s.verifierLock.Unlock()
	s.verifier = verifier
}
