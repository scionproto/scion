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
package certs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-ini/ini"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var (
	iaRe *regexp.Regexp = regexp.MustCompile("ISD([0-9]+)/AS([0-9]+)")
)

func runTemplate(cmd *base.Command, args []string) {
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
	fmt.Println("Generating cert config templates.")
	if err := filepath.Walk(top, visitTemplate); err != nil {
		base.ErrorAndExit("Failed generating template: %s\n", err)
	}
}

func visitTemplate(path string, info os.FileInfo, visitError error) error {
	if visitError != nil {
		return visitError
	}
	// If not an AS directory, keep walking.
	if !info.IsDir() || !strings.HasPrefix(info.Name(), "AS") {
		return nil
	}
	ia, err := getIAFromPath(path)
	if err != nil {
		return err
	}
	c := newTemplateCertConf(ia, core)
	iniCfg := ini.Empty()
	err = ini.ReflectFrom(iniCfg, c)
	if err != nil {
		return err
	}
	fname := getConfName(core)
	fpath := filepath.Join(path, fname)
	// Check if file exists and do not override without -f
	if !pkicmn.Force {
		// Check if the file already exists.
		if _, err = os.Stat(fpath); err == nil {
			fmt.Printf("%s already exists. Use -f to overwrite.\n", fpath)
			return nil
		}
	}
	err = iniCfg.SaveTo(fpath)
	if err != nil {
		return err
	}
	// Skip the rest of this directory.
	return filepath.SkipDir
}

func getIAFromPath(path string) (*addr.ISD_AS, error) {
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
