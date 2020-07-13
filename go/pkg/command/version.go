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

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/env"
)

// NewVersion creates a command that displays the SCION version information.
func NewVersion(pather Pather) *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "version",
		Short:   "Show the SCION version information",
		Example: fmt.Sprintf("  %[1]s version", pather.CommandPath()),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(env.VersionInfo())
		},
	}
	return cmd
}
