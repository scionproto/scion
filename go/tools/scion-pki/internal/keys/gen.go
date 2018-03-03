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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

func runGenKey(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	top, err := pkicmn.ProcessSelector(args[0], args[1:], false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	if err := filepath.Walk(top, visitKeys); err != nil && err != filepath.SkipDir {
		base.ErrorAndExit("%s\n", err)
	}
	os.Exit(0)
}

func visitKeys(path string, info os.FileInfo, visitError error) error {
	if visitError != nil {
		return visitError
	}
	if !info.IsDir() || !strings.HasPrefix(info.Name(), "AS") {
		return nil
	}
	ia, err := pkicmn.GetIAFromPath(path)
	if err != nil {
		return common.NewBasicError("Invalid path", nil, "path", path)
	}
	fmt.Println("Generating keys for", ia)
	kpath := filepath.Join(path, "keys")
	if all {
		return GenAll(kpath, core)
	}
	if sign {
		if err := GenKey(trust.SigKeyFile, kpath, genSignKey, true); err != nil {
			return err
		}
	}
	if coreSign {
		if err := GenKey(trust.CoreSigKeyFile, kpath, genSignKey, true); err != nil {
			return err
		}
	}
	if dec {
		if err := GenKey(trust.DecKeyFile, kpath, genEncKey, true); err != nil {
			return err
		}
	}
	if online {
		if err := GenKey(trust.OnKeyFile, kpath, genSignKey, false); err != nil {
			return err
		}
	}
	if offline {
		if err := GenKey(trust.OffKeyFile, kpath, genSignKey, false); err != nil {
			return err
		}
	}
	if master {
		if err := GenKey(masterKeyFname, kpath, genMasterKey, false); err != nil {
			return err
		}
	}
	return filepath.SkipDir
}

type keyGenFunc func(io.Reader) ([]byte, error)

func GenKey(fname, outDir string, keyGenF keyGenFunc, writeSeed bool) error {
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
	if !writeSeed {
		return nil
	}
	// Write seed to file.
	seedFname := strings.TrimSuffix(fname, filepath.Ext(fname)) + seedFileExt
	seedPath := filepath.Join(outDir, seedFname)
	seedEnc := base64.StdEncoding.EncodeToString(seed)
	if err = pkicmn.WriteToFile([]byte(seedEnc), seedPath, 0600); err != nil {
		return common.NewBasicError("Cannot write seed file", err, "seed", seedFname)
	}
	return nil
}

func genSignKey(rand io.Reader) ([]byte, error) {
	_, private, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return private, nil
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

func GenAll(outDir string, core bool) error {
	// Generate AS sigining and decryption keys.
	if err := GenKey(trust.SigKeyFile, outDir, genSignKey, true); err != nil {
		return err
	}
	if err := GenKey(trust.DecKeyFile, outDir, genEncKey, true); err != nil {
		return err
	}
	// Generate AS master key.
	if err := GenKey(masterKeyFname, outDir, genMasterKey, false); err != nil {
		return err
	}
	if !core {
		return nil
	}
	// Generate core signing key.
	if err := GenKey(trust.CoreSigKeyFile, outDir, genSignKey, true); err != nil {
		return err
	}
	// Generate offline and online root keys if core was specified.
	if err := GenKey(trust.OffKeyFile, outDir, genSignKey, false); err != nil {
		return err
	}
	return GenKey(trust.OnKeyFile, outDir, genSignKey, false)
}
