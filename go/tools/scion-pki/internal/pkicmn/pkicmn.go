// Copyright 2017 ETH Zurich
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
	"regexp"
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
	iaRe    *regexp.Regexp = regexp.MustCompile("ISD([0-9]+)/AS([0-9]+)")
)

// ProcessSelector processes the given selector and returns the top level directory
// to which the requested operation should be applied.
func ProcessSelector(selector string) ([]string, [][]string, error) {
	toks := strings.Split(selector, "-")
	if len(toks) != 2 {
		return nil, nil, common.NewBasicError(ErrInvalidSelector, nil, "selector", selector)
	}
	isdTok := toks[0]
	asTok := toks[1]
	// Sanity check selector.
	if isdTok == "*" && asTok != "*" {
		return nil, nil, common.NewBasicError(ErrInvalidSelector, nil, "selector", selector)
	}
	if isdTok != "*" {
		if _, err := strconv.ParseUint(isdTok, 10, 12); err != nil {
			return nil, nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
	}
	if asTok != "*" {
		if _, err := strconv.ParseUint(asTok, 10, 20); err != nil {
			return nil, nil, common.NewBasicError(ErrInvalidSelector, err, "selector", selector)
		}
	}
	absRoot, err := filepath.Abs(RootDir)
	if err != nil {
		return nil, nil, err
	}
	isdGlob := fmt.Sprintf("ISD%s", isdTok)
	isdDirs, err := filepath.Glob(filepath.Join(absRoot, isdGlob))
	if err != nil {
		return nil, nil, err
	}
	var asDirs [][]string
	for _, dir := range isdDirs {
		asGlob := fmt.Sprintf("%s/AS%s", filepath.Base(dir), asTok)
		dirs, err := filepath.Glob(filepath.Join(absRoot, asGlob))
		if err != nil {
			return nil, nil, err
		}
		asDirs = append(asDirs, dirs)
	}
	return isdDirs, asDirs, nil
}

// FilterASDirs takes a list of paths and returns a list of paths corresponding to core ASes
// and a list of paths for all remaining ASes.
func FilterASDirs(asDirs []string, cores []*addr.ISD_AS) ([]string, []string) {
	var cdirs, dirs []string
OUTER:
	for _, dir := range asDirs {
		for _, cia := range cores {
			if dir == GetPath(cia) {
				cdirs = append(cdirs, dir)
				continue OUTER
			}
		}
		dirs = append(dirs, dir)
	}
	return cdirs, dirs
}

func WriteToFile(raw common.RawBytes, path string, perm os.FileMode) error {
	if !Force {
		// Check if file already exists.
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
	}
	if err := ioutil.WriteFile(path, append(raw, "\n"...), perm); err != nil {
		return err
	}
	fmt.Println("Successfully written", path)
	return nil
}

func GetPath(ia *addr.ISD_AS) string {
	absRoot, err := filepath.Abs(RootDir)
	if err != nil {
		panic(err)
	}
	return filepath.Join(absRoot, fmt.Sprintf("ISD%d/AS%d", ia.I, ia.A))
}

func GetIAFromPath(path string) (*addr.ISD_AS, error) {
	match := iaRe.FindAllStringSubmatch(path, -1)
	if len(match) != 1 || len(match[0]) != 3 {
		return nil, common.NewBasicError("Path not valid", nil, "path", path)
	}
	isd, err := strconv.Atoi(match[0][1])
	if err != nil {
		return nil, err
	}
	as, err := strconv.Atoi(match[0][2])
	if err != nil {
		return nil, err
	}
	return &addr.ISD_AS{I: isd, A: as}, nil
}
