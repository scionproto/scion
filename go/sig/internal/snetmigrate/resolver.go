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

package snetmigrate

import (
	"context"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/sig/internal/pathmgr"
)

func ResolverFromSD(sciondPath string, pathCount uint16) (pathmgr.Resolver, error) {
	var pathResolver pathmgr.Resolver
	if sciondPath != "" {
		sciondConn, err := sciond.NewService(sciondPath).Connect(
			context.Background())
		if err != nil {
			return nil, serrors.WrapStr("Unable to initialize SCIOND service", err)
		}
		pathResolver = pathmgr.New(sciondConn, pathmgr.Timers{}, pathCount)
	}
	return pathResolver, nil
}
