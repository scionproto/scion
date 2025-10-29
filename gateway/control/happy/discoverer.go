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

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/connect/happy"
)

type Discoverer struct {
	Connect   control.Discoverer
	Grpc      control.Discoverer
	RpcConfig happy.Config
}

func (d Discoverer) Gateways(ctx context.Context) ([]control.Gateway, error) {
	return happy.Happy(
		ctx,
		happy.Call0[[]control.Gateway]{
			Call: d.Connect.Gateways,
			Typ:  "discovery.v1.DiscoveryService.Gateways",
		},
		happy.Call0[[]control.Gateway]{
			Call: d.Grpc.Gateways,
			Typ:  "discovery.v1.DiscoveryService.Gateways",
		},
		d.RpcConfig,
	)
}
