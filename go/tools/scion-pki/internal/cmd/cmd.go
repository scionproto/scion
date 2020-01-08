// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/certs"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/tmpl"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/trc"
	v2 "github.com/scionproto/scion/go/tools/scion-pki/internal/v2/cmd"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/version"
)

var RootCmd = &cobra.Command{
	Use:   "scion-pki",
	Short: "Scion Public Key Infrastructure Management Tool",
	Long: `scion-pki is a tool to generate keys, certificates, and trust
root configuration files used in the SCION control plane PKI.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize global OutDir if not set on the cmdline.
		if pkicmn.OutDir == "" {
			pkicmn.OutDir = pkicmn.RootDir
		}
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

const completionDir string = "/tmp/scion-pki"

var scripts = map[string]struct {
	FileName     string
	Gen          func(string) error
	Instructions string
}{
	"bash": {
		FileName:     "scion_pki_bash",
		Gen:          RootCmd.GenBashCompletionFile,
		Instructions: bashInstr,
	},
	"zsh": {
		FileName:     "_scion-pki",
		Gen:          RootCmd.GenZshCompletionFile,
		Instructions: zshInstr,
	},
}

var autoCompleteCmd = &cobra.Command{
	Use:   "autocomplete",
	Short: "Generate autocomplete files for bash and zsh",
	RunE: func(cmd *cobra.Command, args []string) error {
		script, ok := scripts[shell]
		if !ok {
			return serrors.New("shell not supported", "type", shell)
		}
		if err := os.MkdirAll(completionDir, 0755); err != nil {
			return err
		}
		name := filepath.Join(completionDir, script.FileName)
		if err := script.Gen(name); err != nil {
			return err
		}
		pkicmn.QuietPrint("Generated: %s\n", name)
		pkicmn.QuietPrint("Instructions: %s", script.Instructions)
		return nil
	},
}

func Execute() {
	err := RootCmd.Execute()
	switch err.(type) {
	case common.BasicError:
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(2)
	case error:
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		RootCmd.Usage()
		os.Exit(1)
	}
}

var shell string

func init() {
	RootCmd.PersistentFlags().BoolVarP(&pkicmn.Force, "force", "f", false,
		"Overwrite existing keys/certs/trcs")
	RootCmd.PersistentFlags().StringVarP(&pkicmn.RootDir, "root", "d", ".",
		"Root directory where scion-pki looks for configuration files. Is also used as output "+
			"directory if -out/-o is not specified.")
	RootCmd.PersistentFlags().StringVarP(&pkicmn.OutDir, "out", "o", "",
		"Output directory where certificates and keys will be placed. Defaults to -root/-d.")
	RootCmd.PersistentFlags().BoolVarP(&pkicmn.Quiet, "quiet", "q", false,
		"Quiet mode, i.e., only errors will be printed.")
	autoCompleteCmd.PersistentFlags().StringVar(&shell, "shell", "bash",
		"Select shell type [bash,zsh]")

	RootCmd.AddCommand(certs.Cmd)
	RootCmd.AddCommand(keys.Cmd)
	RootCmd.AddCommand(version.Cmd)
	RootCmd.AddCommand(trc.Cmd)
	RootCmd.AddCommand(tmpl.Cmd)
	RootCmd.AddCommand(autoCompleteCmd)
	RootCmd.AddCommand(v2.Cmd)
}
