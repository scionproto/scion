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

// Package instructions prints and writes the run/teardown instructions for the
// generated topology. It is a no-op placeholder for the MVP; the implementation
// lands in a follow-up alongside the clab phase.
package instructions

import (
	"fmt"
	"io"

	"github.com/scionproto/scion/tools/testgen/out"
)

// Write prints and writes the run instructions. Currently a no-op.
func Write(_ out.Dir, w io.Writer) error {
	fmt.Fprintln(w, "instructions: run instructions are not yet implemented (no-op)")
	return nil
}
