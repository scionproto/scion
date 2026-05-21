// Copyright 2026 SCION Association
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

//go:build (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64 || wasm) && linux

package ebpf

import "testing"

// Checks DropReasonNames has no empty or duplicate entries.
func TestDropReasonNames(t *testing.T) {
	seen := map[string]int{}
	for i, name := range DropReasonNames {
		if name == "" {
			t.Errorf("DropReasonNames[%d] is empty", i)
		}
		if prior, dup := seen[name]; dup {
			t.Errorf("duplicate DropReasonNames entry %q at index %d and %d",
				name, prior, i)
		}
		seen[name] = i
	}
}
