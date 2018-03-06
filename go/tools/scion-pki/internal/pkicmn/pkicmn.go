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

// ProcessSelector processes the given selector and returns the top level directory
// to which the requested operation should be applied.
func ProcessSelector(selector string) (map[int][]*addr.ISD_AS, error) {
	toks := strings.Split(selector, "-")
	if len(toks) != 2 {
		return nil, common.NewBasicError(ErrInvalidSelector, nil, "selector", selector)
	}
	isdTok := toks[0]
	asTok := toks[1]
	// Sanity check selector.
	if isdTok == "*" && asTok != "*" {
		return nil, common.NewBasicError(ErrInvalidSelector, nil, "selector", selector)
	}
	if isdTok != "*" {
		if _, err := strconv.ParseUint(isdTok, 10, 12); err != nil {
			return nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
	}
	if asTok != "*" {
		if _, err := strconv.ParseUint(asTok, 10, 20); err != nil {
			return nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
	}
	isdGlob := fmt.Sprintf("ISD%s", isdTok)
	isdDirs, err := filepath.Glob(filepath.Join(RootDir, isdGlob))
	if err != nil {
		return nil, err
	}
	res := make(map[int][]*addr.ISD_AS)
	for _, dir := range isdDirs {
		base := filepath.Base(dir)
		isd, err := strconv.ParseUint(base[3:], 10, 12)
		if err != nil {
			return nil, common.NewBasicError("Invalid path", nil, "path", dir)
		}
		asGlob := fmt.Sprintf("%s/AS%s", base, asTok)
		dirs, err := filepath.Glob(filepath.Join(RootDir, asGlob))
		if err != nil {
			return nil, err
		}
		ases := make([]*addr.ISD_AS, len(dirs))
		for i, asDir := range dirs {
			as, err := strconv.ParseUint(filepath.Base(asDir)[2:], 10, 22)
			if err != nil {
				return nil, common.NewBasicError("Invalid path", nil, "path", asDir)
			}
			ases[i] = &addr.ISD_AS{I: int(isd), A: int(as)}
		}
		res[int(isd)] = ases
	}
	return res, nil
}

// FilterASDirs takes a list of paths and returns a list of paths corresponding to core ASes
// and a list of paths for all remaining ASes.
func FilterAses(ases, cores []*addr.ISD_AS) []*addr.ISD_AS {
	var filtered []*addr.ISD_AS
OUTER:
	for _, ia := range ases {
		for _, cia := range cores {
			if ia.Eq(cia) {
				continue OUTER
			}
		}
		filtered = append(filtered, ia.Copy())
	}
	return filtered
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

func GetAsPath(ia *addr.ISD_AS) string {
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d/AS%d", ia.I, ia.A))
}

func GetIsdPath(isd int) string {
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d", isd))
}
