// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// NewCompletion creates a command that provides bash completion.
func NewCompletion(pather Pather) *cobra.Command {
	var flags struct {
		shell string
	}
	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Generates shell completion scripts",
		Long: fmt.Sprintf(`Outputs the autocomplete configuration for some shells.

For example, you can add autocompletion for your current bash session using:

    . <( %[1]s completion )

To permanently add bash autocompletion, run:

    %[1]s completion > /etc/bash_completion.d/%[1]s
`, pather.CommandPath()),
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
				return fmt.Errorf("unknown shell: %s", flags.shell)
			}
		},
	}
	cmd.Flags().StringVar(&flags.shell, "shell", "bash", "Shell type (bash|zsh|fish)")
	return cmd
}
