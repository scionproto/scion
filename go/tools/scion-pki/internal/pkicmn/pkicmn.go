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
func ProcessSelector(option string, args []string) (string, error) {
	toks := strings.Split(option, "-")
	if len(toks) != 2 {
		return "", common.NewBasicError(ErrInvalidSelector, nil, "selector", option)
	}
	isdTok := toks[0]
	asTok := toks[1]
	if isdTok == "*" {
		if asTok != "*" {
			return "", common.NewBasicError(ErrInvalidSelector, nil, "selector", option)
		}
		return RootDir, nil
	}
	isd, err := strconv.Atoi(isdTok)
	if err != nil {
		return "", common.NewBasicError(ErrInvalidSelector, nil, "selector", option)
	}
	if asTok == "*" {
		return filepath.Join(RootDir, fmt.Sprintf("ISD%d", isd)), nil
	}
	as, err := strconv.Atoi(asTok)
	if err != nil {
		return "", common.NewBasicError(ErrInvalidSelector, nil, "selector", option)
	}
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d/AS%d", isd, as)), nil
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
	return filepath.Join(RootDir, fmt.Sprintf("ISD%d/AS%d", ia.I, ia.A))
}
