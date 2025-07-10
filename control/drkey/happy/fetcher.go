// Copyright 2025 SCION Association, Anapaya Systems
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

package happy

import (
	"context"

	"github.com/scionproto/scion/control/drkey"
	"github.com/scionproto/scion/pkg/connect/happy"
	libdrkey "github.com/scionproto/scion/pkg/drkey"
)

type Fetcher struct {
	Connect drkey.Fetcher
	Grpc    drkey.Fetcher
}

func (f Fetcher) Level1(ctx context.Context, meta libdrkey.Level1Meta) (libdrkey.Level1Key, error) {
	return happy.Happy(
		ctx,
		happy.Call1[libdrkey.Level1Meta, libdrkey.Level1Key]{
			Call:   f.Connect.Level1,
			Input1: meta,
			Typ:    "control_plane.v1.DRKeyInterService.DRKeyLevel1",
		},
		happy.Call1[libdrkey.Level1Meta, libdrkey.Level1Key]{
			Call:   f.Grpc.Level1,
			Input1: meta,
			Typ:    "control_plane.v1.DRKeyInterService.DRKeyLevel1",
		},
		happy.Config{},
	)
}
