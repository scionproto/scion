// Copyright 2026 Anapaya Systems
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

// Package clab generates the containerlab topology file from the resolved
// network. It is a no-op placeholder for the MVP; the implementation lands in a
// follow-up. The hydrate.Network already carries the per-link subnets,
// per-service addresses and interface bindings the implementation will need.
package clab

import (
	"fmt"
	"io"

	"github.com/scionproto/scion/tools/testgen/hydrate"
	"github.com/scionproto/scion/tools/testgen/out"
)

// Generate writes the containerlab topology file. Currently a no-op.
func Generate(_ *hydrate.Network, _ out.Dir, w io.Writer) error {
	fmt.Fprintln(w, "clab: containerlab topology generation is not yet implemented (no-op)")
	return nil
}
