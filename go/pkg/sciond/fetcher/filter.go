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

package fetcher

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

// Policy is a filter on path sets.
type Policy interface {
	Filter(pathpol.PathSet) pathpol.PathSet
}

// Filter filters the given paths with the given policy. Note that this
// function might change the order of elements.
func Filter(paths []*combinator.Path, policy Policy) []*combinator.Path {
	return psToPaths(policy.Filter(pathsToPs(paths)))
}

func pathsToPs(paths []*combinator.Path) pathpol.PathSet {
	ps := make(pathpol.PathSet, len(paths))
	for _, path := range paths {
		wp := newPathWrap(path)
		ps[wp.key] = wp
	}
	return ps
}

func psToPaths(ps pathpol.PathSet) []*combinator.Path {
	paths := make([]*combinator.Path, 0, len(ps))
	for _, wp := range ps {
		paths = append(paths, wp.(pathWrap).origPath)
	}
	return paths
}

type pathWrap struct {
	key      snet.PathFingerprint
	intfs    []snet.PathInterface
	origPath *combinator.Path
}

func newPathWrap(p *combinator.Path) pathWrap {
	intfs := make([]snet.PathInterface, 0, len(p.Interfaces))
	keyParts := make([]string, 0, len(p.Interfaces))
	for _, intf := range p.Interfaces {
		intfs = append(intfs, intf)
		keyParts = append(keyParts, fmt.Sprintf("%s#%d", intf.IA(), intf.ID()))
	}
	return pathWrap{
		key:      snet.PathFingerprint(strings.Join(keyParts, " ")),
		intfs:    intfs,
		origPath: p,
	}
}

func (p pathWrap) Interfaces() []snet.PathInterface { return p.intfs }
