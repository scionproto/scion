// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package segsaver contains helper methods to save segments and revocations.
package segsaver

import (
	"context"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
)

// StoreSeg saves s to the given pathDB. In case of failure the error is
// returned. The returned boolean is true if the segment was inserted in
// the database.
func StoreSeg(ctx context.Context, s *seg.Meta, pathDB pathdb.PathDB) (bool, error) {
	n, err := pathDB.Insert(ctx, s)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
