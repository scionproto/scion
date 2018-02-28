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

// Package keys provides a generator for AS-level keys involved in the SCION
// control plane PKI.
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

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

const (
	seedFileExt    = ".seed"
	masterKeyFname = "master.key"
)

var CmdKeys = &base.Command{
	Name:      "keys",
	Run:       runKeys,
	UsageLine: "keys [-h] (gen|clean) [<flags>] selector",
	Short:     "Generate keys for the SCION control plane PKI.",
	Long: `
'keys' can be used to generate all the necessary keys used in the SCION control plane PKI as well
as the AS master key.

Subcommands:
	gen
		Used to generate new keys.
	clean (NOT IMPLEMENTED)
		Used to remove all keys.

Flags:
	-d
		The root directory of all certificates and keys (default '.')
	-f
		Overwrite existing keys.
	-core
		Used with -all to generate core keys types as well.
	-all
		Generate all keys.
	-sign
		Generate the AS signing key.
	-dec
		Generate the AS decryption key.
	-online
		Generate the AS online root key.
	-offline
		Generate the AS offline root key.
	-master
		Generate the AS master key.

Selector:
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-11
`,
}

var (
	core     bool
	all      bool
	dec      bool
	sign     bool
	coreSign bool
	online   bool
	offline  bool
	master   bool
)

func init() {
	CmdKeys.Flag.StringVar(&pkicmn.RootDir, "d", ".", "")
	CmdKeys.Flag.BoolVar(&pkicmn.Force, "f", false, "")
	CmdKeys.Flag.BoolVar(&core, "core", false, "")
	CmdKeys.Flag.BoolVar(&all, "all", false, "")
	CmdKeys.Flag.BoolVar(&dec, "dec", false, "")
	CmdKeys.Flag.BoolVar(&sign, "sign", false, "")
	CmdKeys.Flag.BoolVar(&coreSign, "core-sign", false, "")
	CmdKeys.Flag.BoolVar(&online, "online", false, "")
	CmdKeys.Flag.BoolVar(&offline, "offline", false, "")
	CmdKeys.Flag.BoolVar(&master, "master", false, "")
}

func runKeys(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	subCmd := args[0]
	cmd.Flag.Parse(args[1:])
	switch subCmd {
	case "gen":
		runGenKey(cmd, cmd.Flag.Args())
	case "clean":
		fmt.Println("clean is not implemented yet.")
		return
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand '%s'\n", args[0])
		fmt.Fprintf(os.Stderr, "run 'scion-pki keys -h' for help.\n")
		os.Exit(2)
	}
}

func runGenKey(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	top, err := pkicmn.ProcessSelector(args[0], args[1:])
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
