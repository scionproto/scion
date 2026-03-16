// Copyright 2026 ETH Zurich
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

package redemption

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/daemon"
	humm "github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func OneShotReservation(
	ctx context.Context,
	sdConn daemon.Connector,
	localIP net.IP,
	p snet.Path,
	commonRequest humm.RedemptionRequestNoHop,
) (*snetpath.Reservation, error) {
	// Build a redemption client.
	redemptClient, err := NewRedemptionClient(ctx, sdConn, localIP)
	if err != nil {
		return nil, serrors.Wrap("new redemption client", err)
	}
	// Obtain the flyovers.
	flyovers, err := redemptClient.RedeemPathWithRequest(ctx, p, commonRequest)
	if err != nil {
		return nil, serrors.Wrap("redeeming flyovers", err)
	}

	// Build a reservation with the flyovers.
	return snetpath.NewReservation(
		snetpath.WithScionPath(p, snetpath.FlyoversToMap(flyovers)),
	)
}
