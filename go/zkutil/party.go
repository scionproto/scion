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

	"github.com/samuel/go-zookeeper/zk"

	"github.com/scionproto/scion/go/lib/log"
)

type Party struct {
	c    *zk.Conn
	ISD  int
	AS   int
	path string
	name string
}

func NewParty(c *zk.Conn, isd, as int, name string) *Party {
	return &Party{c, isd, as, fmt.Sprintf(isdAsPath(isd, as)), name}
}

func (p *Party) Join() error {
	if err := EnsurePath(p.c, p.path); err != nil {
		return err
	}
	acl := zk.WorldACL(zk.PermAll)
	path, err := p.c.CreateProtectedEphemeralSequential(
		fmt.Sprintf("%s/%s", p.path, p.name), []byte(p.name), acl)
	if err != nil {
		return err
	}
	log.Debug("(party) Joined", "path", path)
	return nil
}
