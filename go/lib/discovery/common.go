// Copyright 2018 Anapaya Systems
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

package discovery

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
)

type Pool interface {
	Update(*topology.Topo) error
	Choose() (Info, error)
}

type Info interface {
	fmt.Stringer
	Update(*addr.AppAddr)
	Addr() *addr.AppAddr
	FailCount() int
	Fail()
}

type Fetcher interface {
	periodic.Task
	UpdateTopo(*topology.Topo) error
}
