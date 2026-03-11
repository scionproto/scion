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
	"net/http"

	"connectrpc.com/connect"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
)

type RedemptionClient struct {
	LocaIA addr.IA
	SdConn daemon.Connector // Daemon connector for paths.
}

func NewRedemptionClient() (*RedemptionClient, error) {
	// TODO
	return nil, nil
}

// RedeemHop redeems one hop.
func RedeemHop(ctx context.Context) {
	client := hbirdv1connect.NewHBirdServiceClient(
		http.DefaultClient,
		"http://localhost:30258",
	)
	request := &hbirdv1.RedemptionRequests{}
	res, err := client.Redeem(ctx, connect.NewRequest(request))
	_ = err
	_ = res
}

func RedeemFullPath() {

}
