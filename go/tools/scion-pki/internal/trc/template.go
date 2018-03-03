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
package trc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-ini/ini"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runTemplate(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	top, err := pkicmn.ProcessSelector(args[0], args[1:], true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	fmt.Println("Generating trc config templates.")
	if err := filepath.Walk(top, visitTemplate); err != nil {
		base.ErrorAndExit("Failed generating template: %s\n", err)
	}
}

func visitTemplate(path string, info os.FileInfo, visitError error) error {
	if visitError != nil {
		return visitError
	}
	// If not an AS directory, keep walking.
	if !info.IsDir() || !strings.HasPrefix(info.Name(), "ISD") {
		return nil
	}
	isd, err := strconv.Atoi(info.Name()[3:])
	if err != nil {
		return err
	}
	fmt.Printf("Generating configuration template for ISD%d\n", isd)
	t := &trcConf{Isd: uint16(isd)}
	iniCfg := ini.Empty()
	if err = ini.ReflectFrom(iniCfg, t); err != nil {
		return err
	}
	if _, err = iniCfg.Section("").NewKey("CoreASes", "0-0,0-0"); err != nil {
		return err
	}
	fpath := filepath.Join(path, trcConfFile)
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
	fmt.Println("Successfully written", fpath)
	// Skip the rest of this directory.
	return filepath.SkipDir
}
