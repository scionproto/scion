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

var completionShell string

// completionCmd represents the completion command
var completionCmd = &cobra.Command{
	Use:   "completion",
	Short: "Generates bash completion scripts",
	Long: `'completion' outputs the autocomplete configuration for some shells.
For example, you can add autocompletion for your current bash session using:

    . <( scion completion )

To permanently add bash autocompletion, run:

    scion completion > /etc/bash_completion.d/scion
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch completionShell {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		default:
			return serrors.New("unknown shell", "input", completionShell)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
	completionCmd.Flags().StringVar(&completionShell, "shell", "bash",
		"Shell type (bash|zsh|fish)")
}
