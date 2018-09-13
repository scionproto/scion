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
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize global OutDir if not set on the cmdline.
		if pkicmn.OutDir == "" {
			pkicmn.OutDir = pkicmn.RootDir
		}
	},
}

const (
	bashCompletionScript string = "scion_pki_bash"
	zshCompletionScript  string = "_scion-pki"
	bashInstruction      string = `
Instructions:
sudo mv scion_pki_bash /etc/bash_completion.d
source ~/.bashrc
`
	zshInstruction string = `
Instructions:
mkdir -p ~/.zsh/completion
mv _scion-pki ~/.zsh/completion
cat <<EOF >> ~/.zshrc
fpath=(~/.zsh/completion \$fpath)
autoload -U compinit
compinit
zstyle ':completion:*' menu select=2
EOF
source ~/.zshrc
`
)

var autoCompleteCmd = &cobra.Command{
	Use:   "autocomplete",
	Short: "Generate autocomplete files for bash and zsh",
	Run: func(cmd *cobra.Command, args []string) {
		if zsh {
			RootCmd.GenZshCompletionFile(zshCompletionScript)
			pkicmn.QuietPrint("Generated %s\n", zshCompletionScript)
			pkicmn.QuietPrint(zshInstruction)
		} else {
			RootCmd.GenBashCompletionFile(bashCompletionScript)
			pkicmn.QuietPrint("Generated %s\n", bashCompletionScript)
			pkicmn.QuietPrint(bashInstruction)
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

var zsh bool

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
	autoCompleteCmd.PersistentFlags().BoolVarP(&zsh, "zsh", "z", false,
		"Generate autocompletion script for zsh")

	RootCmd.AddCommand(certs.Cmd)
	RootCmd.AddCommand(keys.Cmd)
	RootCmd.AddCommand(version.Cmd)
	RootCmd.AddCommand(trc.Cmd)
	RootCmd.AddCommand(tmpl.Cmd)
	RootCmd.AddCommand(autoCompleteCmd)
}
