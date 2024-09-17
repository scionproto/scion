// Copyright 2024 Anapaya Systems
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

// Package xhack contains hacks that are used to work around limitations in the
// standard library or other packages.
package xhack

// AsynctimerchanOn enables the asynctimerchan debug option. This option disable
// the new timer behavior that was introduced in Go 1.23 (see
// https://tip.golang.org/doc/go1.23#timer-changes).
//
// The semantical change is not handled well by some of our dependencies. Most
// notably, quic-go (see https://github.com/quic-go/quic-go/pull/4659).
//
// This function should be called at the beginning of the main function of the
// applications that have a dependency (direct or indirect) on quic-go.
func AsynctimerchanOn() {
	//FIXME if d := os.Getenv("GODEBUG"); !strings.Contains(d, "asynctimerchan") {
	//	os.Setenv("GODEBUG", d+",asynctimerchan=1")
	//}
}
