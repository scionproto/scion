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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	CertNameFmt     = "ISD%d-AS%d-V%d.crt"
	CoreCertNameFmt = "ISD%d-AS%d-V%d-core.crt"
	TrcNameFmt      = "ISD%d-V%d.trc"
)

var (
	RootDir string
	Force   bool
)

// ProcessSelector processes the given selector and returns the top level directory
// to which the requested operation should be applied.
func ProcessSelector(option string, args []string) (string, error) {
	var top string
	switch option {
	case "all":
		top = RootDir
	case "isd":
		if len(args) != 1 {
			return "", common.NewBasicError("isd id missing", nil)
		}
		isd, err := strconv.Atoi(args[0])
		if err != nil {
			return "", common.NewBasicError("Failed parsing isd arg", err)
		}
		top = filepath.Join(RootDir, fmt.Sprintf("ISD%d", isd))
	case "as":
		if len(args) != 1 {
			return "", common.NewBasicError("as id missing", nil)
		}
		ia, err := addr.IAFromString(args[0])
		if err != nil {
			return "", common.NewBasicError("Failed parsing as arg", err)
		}
		top = filepath.Join(RootDir, fmt.Sprintf("ISD%d/AS%d", ia.I, ia.A))
	default:
		return "", common.NewBasicError("Unrecognized option", nil, "option", option)
	}
	return top, nil
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
	return nil
}
