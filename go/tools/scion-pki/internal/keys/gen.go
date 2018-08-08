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

package keys

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/scionproto/scion/go/lib/as_conf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenKey(args []string) {
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("Error: %s\n", err)
	}
	for isd, ases := range asMap {
		iconf, err := conf.LoadIsdConf(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
		if err != nil {
			pkicmn.ErrorAndExit("Error reading isd.ini: %s\n", err)
		}
		for _, ia := range ases {
			dir := pkicmn.GetAsPath(pkicmn.OutDir, ia)
			core := pkicmn.Contains(iconf.Trc.CoreIAs, ia)
			pkicmn.QuietPrint("Generating keys for %s\n", ia)
			if err = genAll(filepath.Join(dir, pkicmn.KeysDir), core); err != nil {
				pkicmn.ErrorAndExit("Error generating keys: %s\n", err)
			}
		}
	}
	os.Exit(0)
}

func genAll(outDir string, core bool) error {
	// Generate AS sigining and decryption keys.
	if err := genKey(trust.SigKeyFile, outDir, genSignKey); err != nil {
		return err
	}
	if err := genKey(trust.DecKeyFile, outDir, genEncKey); err != nil {
		return err
	}
	// Generate AS master keys.
	if err := genKey(as_conf.MasterKey0, outDir, genMasterKey); err != nil {
		return err
	}
	if err := genKey(as_conf.MasterKey1, outDir, genMasterKey); err != nil {
		return err
	}
	if !core {
		return nil
	}
	// Generate core signing key.
	if err := genKey(trust.IssSigKeyFile, outDir, genSignKey); err != nil {
		return err
	}
	// Generate offline and online root keys if core was specified.
	if err := genKey(trust.OffKeyFile, outDir, genSignKey); err != nil {
		return err
	}
	return genKey(trust.OnKeyFile, outDir, genSignKey)
}

type keyGenFunc func(io.Reader) ([]byte, error)

func genKey(fname, outDir string, keyGenF keyGenFunc) error {
	// Check if out directory exists and if not create it.
	_, err := os.Stat(outDir)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(outDir, 0700); err != nil {
			return common.NewBasicError("Cannot create output dir", err, "key", fname)
		}
	} else if err != nil {
		return common.NewBasicError("Error checking output dir", err, "key", fname)
	}
	// Generate the seed for the public/private key pair.
	seed := make([]byte, 32)
	_, err = rand.Read(seed)
	if err != nil {
		return common.NewBasicError("Error generating key seed", err, "key", fname)
	}
	// Generate a fresh public/private key pair based on seed.
	privKey, err := keyGenF(bytes.NewReader(seed))
	if err != nil {
		return common.NewBasicError("Error generating keys", err, "key", fname)
	}
	// Write private key to file.
	privKeyPath := filepath.Join(outDir, fname)
	privKeyEnc := base64.StdEncoding.EncodeToString(privKey)
	if err = pkicmn.WriteToFile([]byte(privKeyEnc), privKeyPath, 0600); err != nil {
		return common.NewBasicError("Cannot write key file", err, "key", fname)
	}
	return nil
}

func genSignKey(rand io.Reader) ([]byte, error) {
	_, private, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return private.Seed(), nil
}

func genEncKey(rand io.Reader) ([]byte, error) {
	_, private, err := box.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return (*private)[:], nil
}

func genMasterKey(rand io.Reader) ([]byte, error) {
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
