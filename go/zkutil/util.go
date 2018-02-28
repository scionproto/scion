// Copyright 2016 ETH Zurich
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

package zkutil

import (
	"fmt"
	"strings"

	"github.com/samuel/go-zookeeper/zk"

	"github.com/scionproto/scion/go/lib/log"
)

func isdAsPath(isd, as int) string {
	return fmt.Sprintf("/%d/%d", isd, as)
}

func EnsurePath(c *zk.Conn, path string) error {
	for _, subpath := range pathIter(path) {
		log.Debug("Checking for subpath", "subpath", subpath)
		if exists, _, err := c.Exists(subpath); err != nil {
			return fmt.Errorf("(EnsurePath) check: %v", err)
		} else if exists {
			continue
		}
		log.Debug("Creating subpath", "subpath", subpath)
		acl := zk.WorldACL(zk.PermAll)
		if _, err := c.Create(subpath, []byte{}, 0, acl); err != nil {
			return fmt.Errorf("(EnsurePath) %q create: %v", subpath, err)
		}
	}
	log.Debug("Ensured path", "path", path)
	return nil
}

func pathIter(path string) []string {
	parts := strings.Split(path, "/")
	ans := make([]string, len(parts)-1)
	for i := range parts[1:] { // skip the empty first part
		ans[i] = strings.Join(parts[:i+2], "/")
	}
	return ans
}
