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

package trust

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
)

// Inspector gives insights into the primary ASes of a given ISD.
type Inspector interface {
	// ByAttributes returns a list of primary ASes in the specified ISD that hold
	// all the requested attributes.
	ByAttributes(ctx context.Context, isd addr.ISD, opts infra.ASInspectorOpts) ([]addr.IA, error)
	// HasAttributes indicates whether an AS holds all the specified attributes.
	// The first return value is always false for non-primary ASes.
	HasAttributes(ctx context.Context, ia addr.IA, opts infra.ASInspectorOpts) (bool, error)
}
