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

package command

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/config"
)

// NewSample creates a command with sampler sub commands.
func NewSample(pather Pather, cmds ...func(Pather) *cobra.Command) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "sample",
		Short: "Display sample files",
	}
	joined := Join(pather, cmd)
	for _, sampler := range cmds {
		cmd.AddCommand(sampler(joined))
	}
	return cmd
}

// NewSampleConfig creates factory that creates a command that displays a sample
// configuration file.
func NewSampleConfig(cfg config.Sampler) func(Pather) *cobra.Command {
	return func(pather Pather) *cobra.Command {
		var cmd = &cobra.Command{
			Use:     "config",
			Short:   "Display sample configuration file",
			Example: fmt.Sprintf("  %[1]s config > cfg.toml", pather.CommandPath()),
			Run: func(cmd *cobra.Command, args []string) {
				(cfg).Sample(os.Stdout, nil, nil)
			},
		}
		return cmd
	}
}
