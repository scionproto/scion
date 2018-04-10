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

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/certs"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/tmpl"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/trc"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/version"
)

var RootCmd = &cobra.Command{
	Use:   "scion-pki",
	Short: "Scion Public Key Infrastructure Management Tool",
	Long: `scion-pki is a tool to generate keys, certificates, and trust
root configuration files used in the SCION control plane PKI.`,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolVarP(&pkicmn.Force, "force", "f", false,
		"Overwrite existing keys/certs/trcs")
	RootCmd.PersistentFlags().StringVarP(&pkicmn.RootDir, "root", "d", ".",
		"root directory of all certificates and keys")

	RootCmd.AddCommand(certs.Cmd)
	RootCmd.AddCommand(keys.Cmd)
	RootCmd.AddCommand(version.Cmd)
	RootCmd.AddCommand(trc.Cmd)
	RootCmd.AddCommand(tmpl.Cmd)
}
