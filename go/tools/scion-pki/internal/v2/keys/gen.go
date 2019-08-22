// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package keys

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func runGenKey(args []string) {
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("Error: %s\n", err)
	}
	for isd, ases := range asMap {
		isdCfg, err := conf.LoadISDCfg(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
		if err != nil {
			pkicmn.ErrorAndExit("Error reading isd.ini: %s\n", err)
		}
		for _, ia := range ases {
			asCfg, err := conf.LoadASCfg(pkicmn.GetAsPath(pkicmn.RootDir, ia))
			if err != nil {
				pkicmn.ErrorAndExit("Error reading as.ini for %s: %s", ia, err)
			}
			as := as{
				cfg:     asCfg,
				outDir:  filepath.Join(pkicmn.GetAsPath(pkicmn.OutDir, ia), pkicmn.KeysDir),
				voting:  pkicmn.ContainsAS(isdCfg.TRC.VotingASes, ia.A),
				issuing: pkicmn.ContainsAS(isdCfg.TRC.IssuingASes, ia.A),
			}
			pkicmn.QuietPrint("Generating keys for %s\n", ia)
			if err = as.gen(); err != nil {
				pkicmn.ErrorAndExit("Error generating keys: %s\n", err)
			}
		}
	}
	os.Exit(0)
}

type as struct {
	cfg     *conf.ASCfg
	outDir  string
	voting  bool
	issuing bool
}

func (a *as) gen() error {
	// Map output key file to algorithm
	keys := map[string]string{
		keyconf.ASSigKeyFile: a.cfg.AS.SignAlgorithm,
		keyconf.ASRevKeyFile: a.cfg.AS.RevAlgorithm,
		keyconf.ASDecKeyFile: a.cfg.AS.EncAlgorithm,
		keyconf.MasterKey0:   keyconf.RawKey,
		keyconf.MasterKey1:   keyconf.RawKey,
	}
	if a.issuing {
		union(keys, map[string]string{
			keyconf.IssuerCertKeyFile: a.cfg.Issuer.IssuingAlgorithm,
			keyconf.IssuerRevKeyFile:  a.cfg.Issuer.RevAlgorithm,
			keyconf.TRCIssuingKeyFile: a.cfg.PrimaryKeyAlgorithms.Issuing,
		})
	}
	if a.voting {
		union(keys, map[string]string{
			keyconf.TRCOnlineKeyFile:  a.cfg.PrimaryKeyAlgorithms.Online,
			keyconf.TRCOfflineKeyFile: a.cfg.PrimaryKeyAlgorithms.Offline,
		})
	}
	// Check if out directory exists and if not create it.
	_, err := os.Stat(a.outDir)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(a.outDir, 0700); err != nil {
			return common.NewBasicError("Cannot create output dir", err)
		}
	} else if err != nil {
		return common.NewBasicError("Error checking output dir", err)
	}
	for file, keyType := range keys {
		if err := a.genKey(file, keyType); err != nil {
			return err
		}
	}
	return nil
}

func (a *as) genKey(fname, keyType string) error {
	privKey, err := genKey(keyType)
	if err != nil {
		return common.NewBasicError("Error generating keys", err, "key", fname)
	}
	// Skip keys that should not be generated.
	if privKey == nil {
		return nil
	}
	// Write private key to file.
	privKeyPath := filepath.Join(a.outDir, fname)
	privKeyEnc := base64.StdEncoding.EncodeToString(privKey)
	if err = pkicmn.WriteToFile([]byte(privKeyEnc), privKeyPath, 0600); err != nil {
		return common.NewBasicError("Cannot write key file", err, "key", fname)
	}
	return nil
}

func genKey(keyType string) ([]byte, error) {
	switch keyType {
	case "":
		return nil, nil
	case keyconf.RawKey:
		return genMasterKey()
	case scrypto.Ed25519:
		_, private, err := scrypto.GenKeyPair(keyType)
		if err != nil {
			return nil, err
		}
		return ed25519.PrivateKey(private).Seed(), nil
	default:
		_, private, err := scrypto.GenKeyPair(keyType)
		return private, err
	}
}

func genMasterKey() ([]byte, error) {
	key := make([]byte, 16)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != 16 {
		return nil, common.NewBasicError("Not enough random bytes", nil)
	}
	return key, nil
}

// union adds entries of b to a.
func union(a, b map[string]string) {
	for k, v := range b {
		a[k] = v
	}
}
