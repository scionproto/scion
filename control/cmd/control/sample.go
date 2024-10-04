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
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app/command"
)

func newSamplePolicy(pather command.Pather) *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "policy",
		Short:   "Display sample policy file",
		Example: fmt.Sprintf("  %[1]s policy > policy.yml", pather.CommandPath()),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sample beacon.Policy
			sample.InitDefaults()
			if err := yaml.NewEncoder(os.Stdout).Encode(sample); err != nil {
				return serrors.Wrap("producing sample policy", err)
			}
			return nil
		},
	}
	return cmd
}
