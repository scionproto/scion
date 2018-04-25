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

// Package pkicmn contains some commonly used functionality and definitions.
package pkicmn

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	CertNameFmt        = "ISD%d-AS%s-V%d.crt"
	CoreCertNameFmt    = "ISD%d-AS%s-V%d-core.crt"
	TrcNameFmt         = "ISD%d-V%d.trc"
	ErrInvalidSelector = "Invalid selector."
	ErrNoISDDirFound   = "No ISD directories found"
	ErrNoASDirFound    = "No AS directories found"
	TRCsDir            = "trcs"
	CertsDir           = "certs"
	KeysDir            = "keys"
)

var (
	RootDir string
	Force   bool
)

// ProcessSelector processes the given selector and returns a mapping from ISD id to ASes
// of that ISD. In case of an ISD-only selector, i.e., a '*' or any number the lists of
// ASes will be empty.
func ProcessSelector(selector string) (map[addr.ISD][]addr.IA, error) {
	toks := strings.Split(selector, "-")
	if len(toks) > 2 {
		return nil, common.NewBasicError(ErrInvalidSelector, nil, "selector", selector)
	}
	isdTok := toks[0]
	asTok := "*"
	if len(toks) == 2 {
		asTok = toks[1]
	}
	// Validate selectors.
	if isdTok == "*" && asTok != "*" {
		return nil, common.NewBasicError(ErrInvalidSelector, nil, "selector", selector)
	}
	if isdTok != "*" {
		if _, err := addr.ISDFromString(isdTok); err != nil {
			return nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
	}
	if asTok != "*" {
		as, err := addr.ASFromString(asTok)
		if err != nil {
			return nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
		asTok = as.FileFmt()
	}
	isdDirs, err := filepath.Glob(filepath.Join(RootDir, fmt.Sprintf("ISD%s", isdTok)))
	if err != nil {
		return nil, err
	}
	if len(isdDirs) == 0 {
		return nil, common.NewBasicError(ErrNoISDDirFound, nil, "selector", selector)
	}
	res := make(map[addr.ISD][]addr.IA)
	for _, dir := range isdDirs {
		isd, err := isdFromDir(dir)
		if err != nil {
			return nil, err
		}
		dirs, err := filepath.Glob(filepath.Join(dir, fmt.Sprintf("AS%s", asTok)))
		if err != nil {
			return nil, err
		}
		if len(dirs) == 0 {
			return nil, common.NewBasicError(ErrNoASDirFound, nil, "selector", selector)
		}
		ases := make([]addr.IA, len(dirs))
		for i, asDir := range dirs {
			as, err := asFromDir(asDir)
			if err != nil {
				return nil, err
			}
			ases[i] = addr.IA{I: addr.ISD(isd), A: addr.AS(as)}
		}
		res[isd] = ases
	}
	return res, nil
}

func isdFromDir(dir string) (addr.ISD, error) {
	isd, err := addr.ISDFromFileFmt(filepath.Base(dir), true)
	if err != nil {
		return 0, common.NewBasicError("Unable to parse ISD number from dir", err, "dir", dir)
	}
	return isd, nil
}

func asFromDir(dir string) (addr.AS, error) {
	as, err := addr.ASFromFileFmt(filepath.Base(dir), true)
	if err != nil {
		return 0, common.NewBasicError("Unable to parse AS number from dir", err, "dir", dir)
	}
	return as, nil
}

func Contains(ases []addr.IA, as addr.IA) bool {
	for _, ia := range ases {
		if ia.Eq(as) {
			return true
		}
	}
	return false
}

func WriteToFile(raw common.RawBytes, path string, perm os.FileMode) error {
	// Check if file already exists.
	if _, err := os.Stat(path); err == nil {
		if !Force {
			fmt.Printf("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
		// Nuke file to ensure correct permissions.
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	if err := ioutil.WriteFile(path, append(raw, "\n"...), perm); err != nil {
		return err
	}
	fmt.Println("Successfully written", path)
	return nil
}

func GetAsPath(ia addr.IA) string {
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d/AS%s", ia.I, ia.A.FileFmt()))
}

func GetIsdPath(isd addr.ISD) string {
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d", isd))
}

func ErrorAndExit(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(2)
}
