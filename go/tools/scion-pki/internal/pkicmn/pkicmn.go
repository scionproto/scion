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
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	CertNameFmt        = "ISD%d-AS%d-V%d.crt"
	CoreCertNameFmt    = "ISD%d-AS%d-V%d-core.crt"
	TrcNameFmt         = "ISD%d-V%d.trc"
	ErrInvalidSelector = "Invalid selector."
)

var (
	RootDir string
	Force   bool
)

// ProcessSelector processes the given selector and returns a mapping from ISD id to ASes
// of that ISD. In case of an ISD-only selector, i.e., a '*' or any number the lists of
// ASes will be empty.
func ProcessSelector(selector string) (map[int][]addr.IA, error) {
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
		if _, err := strconv.ParseUint(isdTok, 10, addr.ISDBits); err != nil {
			return nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
	}

	if asTok != "*" {
		if _, err := strconv.ParseUint(asTok, 10, addr.ASBits); err != nil {
			return nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
	}
	isdDirs, err := filepath.Glob(filepath.Join(RootDir, fmt.Sprintf("ISD%s", isdTok)))
	if err != nil {
		return nil, err
	}
	if len(isdDirs) == 0 {
		return nil, common.NewBasicError("No directories found", nil, "selector", selector)
	}
	res := make(map[int][]addr.IA)
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
			return nil, common.NewBasicError("No directories found", nil, "selector", selector)
		}
		ases := make([]addr.IA, len(dirs))
		for i, asDir := range dirs {
			as, err := asFromDir(asDir)
			if err != nil {
				return nil, err
			}
			ases[i] = addr.IA{I: int(isd), A: int(as)}
		}
		res[int(isd)] = ases
	}
	return res, nil
}

func isdFromDir(dir string) (uint64, error) {
	isd, err := strconv.ParseUint(filepath.Base(dir)[3:], 10, addr.ISDBits)
	if err != nil {
		return 0, common.NewBasicError("Unable to parse ISD number from dir", nil, "dir", dir)
	}
	return isd, nil
}

func asFromDir(dir string) (uint64, error) {
	as, err := strconv.ParseUint(filepath.Base(dir)[2:], 10, addr.ASBits)
	if err != nil {
		return 0, common.NewBasicError("Unable to parse AS number from dir", nil, "dir", dir)
	}
	return as, nil
}

// FilterAses returns a list of ASes with entries from 'ases' that are not in 'cores'.
func FilterAses(ases, cores []addr.IA) []addr.IA {
	var filtered []addr.IA
	for _, ia := range ases {
		if Contains(cores, ia) {
			continue
		}
		filtered = append(filtered, ia)
	}
	return filtered
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
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d/AS%d", ia.I, ia.A))
}

func GetIsdPath(isd int) string {
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d", isd))
}
