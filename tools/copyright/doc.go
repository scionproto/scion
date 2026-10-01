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

// Command copyright adds a current-year copyright claim to changed Go files:
//
//	go run ./tools/copyright -affiliation "SCION Association"
//	# the same through Bazel
//	make copyright-update AFFILIATION="SCION Association"
//
// The comparison starts at the merge base with upstream/master, or origin/master
// if upstream/master does not exist. It includes untracked files.
package main
