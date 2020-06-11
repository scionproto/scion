// Copyright 2020 Anapaya Systems
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

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/serrors"
)

func newCompletion() *cobra.Command {
	var flags struct {
		shell string
	}

	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion scripts",
		Long: `'completion' outputs the autocomplete configuration for some shells.
For example, you can add autocompletion for your current bash session using:

	. <( scion-pki completion )

To permanently add bash autocompletion, run:

	scion-pki completion > /etc/bash_completion.d/scion_pki
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			switch flags.shell {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			default:
				return serrors.New("unknown shell", "input", flags.shell)
			}
		},
	}

	cmd.Flags().StringVar(&flags.shell, "shell", "bash",
		"Shell type (bash|zsh|fish)")
	return cmd
}
