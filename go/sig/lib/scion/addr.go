// Copyright 2017 ETH Zurich
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

package scion

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

// SCIONAppAddr implements net.Addr
type SCIONAppAddr struct {
	ia   *addr.ISD_AS
	host addr.HostAddr
	port uint16
	path sciond.PathReplyEntry
}

func (sa *SCIONAppAddr) Network() string {
	return "scion"
}

func (sa *SCIONAppAddr) String() string {
	return fmt.Sprintf("%v,%v,%v,%x", sa.ia, sa.host, sa.port, sa.path)
}
