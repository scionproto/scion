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

package e2e

import "strings"

// Docker builds command lines for the docker CLI inside containerlab nodes. Its
// command is a (possibly multi-word) docker invocation, e.g. "docker" or
// "sudo docker".
type Docker struct {
	Cmd string
}

// Argv splits the docker command into the executable and its leading arguments,
// then appends args. The result is ready for exec.Command(name, argv...).
func (d Docker) Argv(args ...string) (name string, argv []string) {
	fields := strings.Fields(d.Cmd)
	return fields[0], append(fields[1:], args...)
}

// Exec builds an `docker exec <container> <bin> <args...>` command line.
func (d Docker) Exec(container, bin string, args ...string) (name string, argv []string) {
	return d.Argv(append([]string{"exec", container, bin}, args...)...)
}
