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
	"crypto/x509"
	"net"

	"github.com/scionproto/scion/pkg/connect/happy"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
)

type Fetcher struct {
	Connect trust.Fetcher
	Grpc    trust.Fetcher
}

func (f Fetcher) Chains(ctx context.Context, query trust.ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	return happy.Happy(
		ctx,
		happy.Call2[trust.ChainQuery, net.Addr, [][]*x509.Certificate]{
			Call:   f.Connect.Chains,
			Input1: query,
			Input2: server,
			Typ:    "control_plane.v1.TrustMaterialService.Chains",
		},
		happy.Call2[trust.ChainQuery, net.Addr, [][]*x509.Certificate]{
			Call:   f.Grpc.Chains,
			Input1: query,
			Input2: server,
			Typ:    "control_plane.v1.TrustMaterialService.Chains",
		},
	)
}

func (f Fetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	return happy.Happy(
		ctx,
		happy.Call2[cppki.TRCID, net.Addr, cppki.SignedTRC]{
			Call:   f.Connect.TRC,
			Input1: id,
			Input2: server,
			Typ:    "control_plane.v1.TrustMaterialService.TRC",
		},
		happy.Call2[cppki.TRCID, net.Addr, cppki.SignedTRC]{
			Call:   f.Grpc.TRC,
			Input1: id,
			Input2: server,
			Typ:    "control_plane.v1.TrustMaterialService.TRC",
		},
	)
}
