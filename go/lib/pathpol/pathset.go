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

package pathpol

import (
	"github.com/scionproto/scion/go/lib/snet"
)

// PathSet is a set of paths. PathSet is used for policy filtering.
type PathSet map[snet.PathFingerprint]Path

// Path describes a path or a partial path, e.g. a segment.
type Path interface {
	// Interfaces returns all the interfaces of this path.
	Interfaces() []snet.PathInterface
}
