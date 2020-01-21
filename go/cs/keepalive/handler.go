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

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/metrics"
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
	Push(ctx context.Context, ifid common.IFIDType)
}

// RevDropper is used to drop revocations from the beacon store for
// interfaces that change their state to active.
type RevDropper interface {
	DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) error
}

// StateChangeTasks holds the tasks that are executed when the state of an
// interface changes to active.
type StateChangeTasks struct {
	IfStatePusher IfStatePusher
	RevDropper    RevDropper
}

// NewHandler returns an infra.Handler for IFID keepalive messages. The state
// change tasks must all be set. Nil tasks will cause the handler to panic.
func NewHandler(ia addr.IA, intfs *ifstate.Interfaces, tasks StateChangeTasks) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &handler{
			ia:      ia,
			request: r,
			intfs:   intfs,
			tasks:   tasks,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)

}

type handler struct {
	ia      addr.IA
	intfs   *ifstate.Interfaces
	tasks   StateChangeTasks
	request *infra.Request
}

// Handle handles IFID keepalive messages.
func (h *handler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	res, err := h.handle(logger)
	if err != nil {
		logger.Error("[KeepaliveHandler] Unable to handle keepalive", "err", err)
	}
	return res
}

func (h *handler) handle(logger log.Logger) (*infra.HandlerResult, error) {
	labels := metrics.KeepaliveLabels{Result: metrics.ErrProcess}
	keepalive, ok := h.request.Message.(*ifid.IFID)
	if !ok {
		metrics.Keepalive.Receives(labels).Inc()
		return infra.MetricsErrInternal, common.NewBasicError(
			"Wrong message type, expected ifid.IFID", nil,
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
	}
	logger.Trace("[KeepaliveHandler] Received", "ifidKeepalive", keepalive)
	ifid, info, err := h.getIntfInfo()
	if err != nil {
		metrics.Keepalive.Receives(labels).Inc()
		return infra.MetricsErrInvalid, err
	}
	labels.IfID = ifid
	if lastState := info.Activate(keepalive.OrigIfID); lastState != ifstate.Active {
		logger.Info("[KeepaliveHandler] Activated interface", "ifid", ifid)
		h.startPush(ifid)
		if err := h.dropRevs(ifid, keepalive.OrigIfID, info.TopoInfo().IA); err != nil {
			metrics.Keepalive.Receives(labels).Inc()
			return infra.MetricsErrInternal, common.NewBasicError("Unable to drop revocations", err)
		}
	}
	logger.Trace("[KeepaliveHandler] Successfully handled", "keepalive", keepalive)
	labels.Result = metrics.Success
	metrics.Keepalive.Receives(labels).Inc()
	return infra.MetricsResultOk, nil
}

func (h *handler) getIntfInfo() (common.IFIDType, *ifstate.Interface, error) {
	peer, ok := h.request.Peer.(*snet.UDPAddr)
	if !ok {
		return 0, nil, common.NewBasicError("Invalid peer address type, expected *snet.UDPAddr",
			nil, "peer", h.request.Peer, "type", common.TypeOf(h.request.Peer))
	}
	hopF, err := peer.Path.GetHopField(peer.Path.HopOff)
	if err != nil {
		return 0, nil, common.NewBasicError("Unable to extract hop field", err)
	}
	info := h.intfs.Get(hopF.ConsIngress)
	if info == nil {
		return 0, nil, common.NewBasicError("Received keepalive for non-existent ifid", nil,
			"ifid", hopF.ConsIngress)
	}
	originIA := info.TopoInfo().IA
	if !info.TopoInfo().IA.Equal(peer.IA) {
		return 0, nil, common.NewBasicError("Keepalive origin IA does not match", nil,
			"ifid", hopF.ConsIngress, "expected", originIA, "actual", peer.IA)
	}
	return hopF.ConsIngress, info, nil
}

func (h *handler) startPush(ifid common.IFIDType) {
	go func() {
		defer log.LogPanicAndExit()
		ctx, cancelF := context.WithTimeout(context.Background(), IfStatePushTimeout)
		defer cancelF()
		h.tasks.IfStatePusher.Push(ctx, ifid)
	}()
}

func (h *handler) dropRevs(localIfid, originIfid common.IFIDType, originIA addr.IA) error {
	subCtx, cancelF := context.WithTimeout(h.request.Context(), DropRevTimeout)
	defer cancelF()
	if err := h.tasks.RevDropper.DeleteRevocation(subCtx, h.ia, localIfid); err != nil {
		return err
	}
	return h.tasks.RevDropper.DeleteRevocation(subCtx, originIA, originIfid)
}
