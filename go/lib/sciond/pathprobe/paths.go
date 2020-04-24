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

// Package pathprobe contains methods to probe scion paths. This is heplful to
// detect path status.
package pathprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// StatusName defines the different states a path can be in.
type StatusName string

const (
	// StatusUnknown indicates that it is not clear what state the path is in.
	StatusUnknown StatusName = "Unknown"
	// StatusTimeout indicates that a reply did come back in time for the path.
	StatusTimeout StatusName = "Timeout"
	// StatusAlive indicates that the expected reply did come back in time.
	StatusAlive StatusName = "Alive"
	// StatusSCMP indicates that an unexpected SCMP packet came in the reply.
	StatusSCMP StatusName = "SCMP"
)

// Status indicates the state a path is in.
type Status struct {
	Status         StatusName
	AdditionalInfo string
}

// Predefined path status
var (
	unknown = Status{Status: StatusUnknown}
	timeout = Status{Status: StatusTimeout}
	alive   = Status{Status: StatusAlive}
)

func (s Status) String() string {
	if s.AdditionalInfo == "" {
		return string(s.Status)
	}
	return fmt.Sprintf("%s(%s)", s.Status, s.AdditionalInfo)
}

// PathKey is the mapping of a path reply entry to a key that is returned in
// GetStatuses.
func PathKey(path snet.Path) string {
	return string(path.Path().Raw)
}

// FilterEmptyPaths removes all empty paths from paths and returns a copy.
func FilterEmptyPaths(paths []snet.Path) []snet.Path {
	if paths == nil {
		return nil
	}
	filtered := make([]snet.Path, 0, len(paths))
	for _, path := range paths {
		if path.Path() != nil && len(path.Path().Raw) > 0 {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

// Prober can be used to get the status of a path.
type Prober struct {
	DstIA   addr.IA
	LocalIA addr.IA
	LocalIP net.IP
}

// GetStatuses probes the paths and returns the statuses of the paths. The
// returned map is keyed with path.Path.FwdPath. The input should only be
// non-empty paths.
func (p Prober) GetStatuses(ctx context.Context,
	paths []snet.Path) (map[string]Status, error) {

	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, serrors.New("deadline required on ctx")
	}

	// Check whether paths are alive. This is done by sending a packet
	// with invalid address via the path. The border router at the destination
	// is going to reply with SCMP error. Receiving the error means that
	// the path is alive.
	pathStatuses := make(map[string]Status, len(paths))
	scmpH := &scmpHandler{statuses: pathStatuses}
	network := snet.NewCustomNetworkWithPR(p.LocalIA,
		&snet.DefaultPacketDispatcherService{
			Dispatcher:  reliable.NewDispatcher(""),
			SCMPHandler: scmpH,
		},
	)
	snetConn, err := network.Listen(ctx, "udp", &net.UDPAddr{IP: p.LocalIP}, addr.SvcNone)
	if err != nil {
		return nil, common.NewBasicError("listening failed", err)
	}
	defer snetConn.Close()
	snetConn.SetDeadline(deadline)
	var sendErrors common.MultiError
	for _, path := range paths {
		scmpH.setStatus(PathKey(path), timeout)
		if err := p.send(snetConn, path); err != nil {
			sendErrors = append(sendErrors, err)
		}
	}
	if err := sendErrors.ToError(); err != nil {
		return nil, err
	}
	var receiveErrors common.MultiError
	for i := len(scmpH.statuses); i > 0; i-- {
		if err := p.receive(snetConn); err != nil {
			receiveErrors = append(receiveErrors, err)
		}
	}
	if err := receiveErrors.ToError(); err != nil {
		return nil, err
	}
	return scmpH.statuses, nil
}

func (p Prober) send(scionConn *snet.Conn, path snet.Path) error {
	addr := &snet.SVCAddr{
		IA:      p.DstIA,
		Path:    path.Path(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcNone,
	}
	log.Debug("Sending test packet.", "path", fmt.Sprintf("%s", path))
	_, err := scionConn.WriteTo([]byte{}, addr)
	if err != nil {
		return common.NewBasicError("cannot send packet", err)
	}
	return nil
}

func (p Prober) receive(scionConn *snet.Conn) error {
	b := make([]byte, 1500, 1500)
	_, _, err := scionConn.ReadFrom(b)
	if err == nil {
		// We've got an actual reply instead of SCMP error. This should not happen.
		return nil
	}
	if errors.Is(err, errBadHost) || errors.Is(err, errSCMP) {
		return nil
	}
	if common.IsTimeoutErr(err) {
		// Timeout expired before all replies were received.
		return nil
	}
	return common.NewBasicError("failed to read packet", err)
}

var errBadHost = errors.New("scmp: bad host")
var errSCMP = errors.New("scmp: other")

type scmpHandler struct {
	mtx      sync.Mutex
	statuses map[string]Status
}

func (h *scmpHandler) Handle(pkt *snet.Packet) error {
	hdr, ok := pkt.L4Header.(*scmp.Hdr)
	if ok {
		path, err := h.path(pkt)
		if err != nil {
			return err
		}
		if hdr.Class == scmp.C_Routing && hdr.Type == scmp.T_R_BadHost {
			h.setStatus(path, alive)
			return errBadHost
		}
		h.setStatus(path, Status{Status: StatusSCMP, AdditionalInfo: hdr.String()})
		return errSCMP
	}
	return nil
}

func (h *scmpHandler) path(pkt *snet.Packet) (string, error) {
	path := pkt.Path.Copy()
	if err := path.Reverse(); err != nil {
		return "", common.NewBasicError("unable to reverse path on received packet", err)
	}
	return string(path.Raw), nil
}

func (h *scmpHandler) setStatus(path string, status Status) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	h.statuses[path] = status
}
