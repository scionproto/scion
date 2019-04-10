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

package keepalive

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// BeaconTimeout is the timeout for beaconing on an activated interface.
	BeaconTimeout = time.Second
	// IfStatePushTimeout is the timeout for pushing interface state info.
	IfStatePushTimeout = time.Second
	// DropRevTimeout is the timeout for dropping revocations.
	DropRevTimeout = time.Second
)

// IfStatePusher is used to push interface state changes to the border
// routers when an interface changes its state to active.
type IfStatePusher interface {
	Push(ctx context.Context)
}

// Beaconer immediately beacons on an interface that changed its state to
// active.
type Beaconer interface {
	Beacon(ctx context.Context, ifid common.IFIDType)
}

// RevDropper is used to drop revocations from the beacon store for
// interfaces that change their state to active.
type RevDropper interface {
	DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) (int, error)
}

// StateChangeTasks holds the tasks that are executed upon a state change
// of an interface to active.
type StateChangeTasks struct {
	IfStatePusher IfStatePusher
	Beaconer      Beaconer
	RevDropper    RevDropper
}

// NewHandler returns an infra.Handler for IFID keepalive messages.
func NewHandler(ia addr.IA, infos *ifstate.Infos, tasks StateChangeTasks) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &handler{
			ia:      ia,
			request: r,
			infos:   infos,
			tasks:   tasks,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)

}

type handler struct {
	ia      addr.IA
	request *infra.Request
	infos   *ifstate.Infos
	tasks   StateChangeTasks
}

// Handle handles IFID keepalive messages.
func (h *handler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	keepalive, ok := h.request.Message.(*ifid.IFID)
	if !ok {
		logger.Error("[KeepaliveHandler] wrong message type, expected ifid.IFID",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	logger.Debug("[KeepaliveHandler] Received", "ifidKeepalive", keepalive)
	peer, ok := h.request.Peer.(*snet.Addr)
	if !ok {
		logger.Error("[KeepaliveHandler] Invalid peer address type, expected *snet.Addr",
			"msg", h.request.Peer, "type", common.TypeOf(h.request.Peer))
		return infra.MetricsErrInternal
	}
	hopF, err := peer.Path.GetHopField(peer.Path.HopOff)
	if err != nil {
		logger.Error("[KeepaliveHandler] Unable to extract hop field", "err", err)
		return infra.MetricsErrInvalid
	}
	info := h.infos.Get(hopF.ConsIngress)
	if info == nil {
		logger.Error("[KeepaliveHandler] Received keepalive for non-existent ifid",
			"ifid", hopF.ConsIngress)
		return infra.MetricsErrInvalid
	}
	remoteIA := info.TopoInfo().ISD_AS
	if !remoteIA.Equal(peer.IA) {
		logger.Error("[KeepaliveHandler] Invalid source IA for keepalive",
			"ifid", hopF.ConsIngress, "expected", remoteIA, "actual", peer.IA)
		return infra.MetricsErrInvalid
	}
	prev := info.Activate(keepalive.OrigIfID)
	if prev != ifstate.Active {
		go func() {
			defer log.LogPanicAndExit()
			ctx, cancelF := context.WithTimeout(context.Background(), BeaconTimeout)
			defer cancelF()
			h.tasks.Beaconer.Beacon(ctx, hopF.ConsIngress)
		}()
		go func() {
			defer log.LogPanicAndExit()
			ctx, cancelF := context.WithTimeout(context.Background(), IfStatePushTimeout)
			defer cancelF()
			h.tasks.IfStatePusher.Push(ctx)
		}()

		if err := h.dropRevs(hopF.ConsIngress, keepalive.OrigIfID, remoteIA); err != nil {
			logger.Error("[KeepaliveHandler] Unable to drop revocations", "err", err)
			return infra.MetricsErrInternal
		}
	}
	return infra.MetricsResultOk
}

func (h *handler) dropRevs(localIfid, remoteIfid common.IFIDType, remoteIA addr.IA) error {
	subCtx, cancelF := context.WithTimeout(h.request.Context(), DropRevTimeout)
	defer cancelF()
	if _, err := h.tasks.RevDropper.DeleteRevocation(subCtx, h.ia, localIfid); err != nil {
		return err
	}
	_, err := h.tasks.RevDropper.DeleteRevocation(subCtx, remoteIA, remoteIfid)
	return err
}
