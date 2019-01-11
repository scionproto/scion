// Copyright 2019 Anapaya Systems
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

package util

import (
	"bufio"
	"os"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
)

// RunsInDocker returns whether the current binary is run in a docker container.
func RunsInDocker() (bool, error) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return false, common.NewBasicError("Failed to open /proc/self/cgroup", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) == 3 && strings.HasPrefix(parts[2], "/docker/") {
			return true, nil
		}
	}
	return false, nil
}
