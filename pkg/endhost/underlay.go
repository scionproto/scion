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

package endhost

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
)

type UnderlayService struct {
	client endhostconnect.UnderlayServiceClient
}

func NewUnderlayService(url string, httpClient *http.Client) *UnderlayService {
	u := &UnderlayService{
		client: endhostconnect.NewUnderlayServiceClient(httpClient, url),
	}
	return u
}

type Underlays struct {
	Udp  *UdpUnderlay
	Snap *SnapUnderlay
}
type UdpUnderlay struct {
	Routers []UdpRouter
}
type UdpRouter struct {
	IsdAs               uint64
	Address             string
	Interfaces          []uint32
	DispatchedPortStart uint32
	DispatchedPortEnd   uint32
}
type SnapUnderlay struct {
	Snaps []Snap
}
type Snap struct {
	Address string
	IsdASes []addr.IA
}

func (u *UnderlayService) ListUnderlays(ctx context.Context, isdAs *addr.IA) (*Underlays, error) {
	var targetIsdAs *uint64
	if isdAs != nil {
		tmp := uint64(*isdAs)
		targetIsdAs = &tmp
	}
	res, err := u.client.ListUnderlays(ctx, &connect.Request[endhost.ListUnderlaysRequest]{
		Msg: &endhost.ListUnderlaysRequest{
			IsdAs: targetIsdAs,
		},
	})
	metricListUnderlaysTotal.Increment(err)
	if err != nil {
		return nil, serrors.Wrap("on ListUnderlays", err)
	}
	underlays := &Underlays{}
	if res.Msg.Udp != nil {
		// udp underlay is available
		underlays.Udp = &UdpUnderlay{}
		for _, router := range res.Msg.Udp.Routers {
			newRouter := UdpRouter{
				IsdAs:      router.IsdAs,
				Address:    router.Address,
				Interfaces: router.Interfaces,
			}
			if router.DispatchedRange != nil {
				newRouter.DispatchedPortStart = router.DispatchedRange.DispatchedPortStart
				newRouter.DispatchedPortEnd = router.DispatchedRange.DispatchedPortEnd
			} else {
				newRouter.DispatchedPortStart = 1
				newRouter.DispatchedPortEnd = 65535
			}
			underlays.Udp.Routers = append(underlays.Udp.Routers, newRouter)
		}
	}
	if res.Msg.Snap != nil {
		// snap underlay is available
		underlays.Snap = &SnapUnderlay{}
		for _, snap := range res.Msg.Snap.Snaps {
			s := Snap{
				Address: snap.Address,
				IsdASes: make([]addr.IA, 0, len(snap.IsdAses)),
			}
			for _, v := range snap.IsdAses {
				s.IsdASes = append(s.IsdASes, addr.IA(v))
			}
			underlays.Snap.Snaps = append(underlays.Snap.Snaps, s)
		}
	}

	return underlays, nil
}
