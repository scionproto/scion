// Copyright 2025 Anapaya Systems
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

package options

// Opt modifies the options.
type Opt[Options any] func(*Options)

// Apply applies the options to the options.
func Apply[Options any](opts []Opt[Options]) Options {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
