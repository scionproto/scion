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

package pathprobe

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	statusUnknown = "Unknown"
	statusTimeout = "Timeout"
	statusAlive   = "Alive"
	statusSCMP    = "SCMP"
)

// PathStatus indicates the state a path is in.
type PathStatus struct {
	status         string
	additionalInfo string
}

// Predefined path status
var (
	Unknown = PathStatus{status: statusUnknown}
	Timeout = PathStatus{status: statusTimeout}
	Alive   = PathStatus{status: statusAlive}
)

func (s PathStatus) String() string {
	if s.additionalInfo == "" {
		return s.status
	}
	return fmt.Sprintf("%s(%s)", s.status, s.additionalInfo)
}

// PathProber can be used to get the status of a path.
type PathProber struct {
	SrcIA addr.IA
	DstIA addr.IA
	Local snet.Addr
}

// GetStatuses probes the paths and returns the statuses of the paths. The
// returned map is keyed with path.Path.FwdPath.
func (p PathProber) GetStatuses(ctx context.Context,
	paths []sciond.PathReplyEntry) (map[string]PathStatus, error) {

	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, common.NewBasicError("deadline required on ctx", nil)
	}
	// Check whether paths are alive. This is done by sending a packet
	// with invalid address via the path. The border router at the destination
	// is going to reply with SCMP error. Receiving the error means that
	// the path is alive.
	pathStatuses := make(map[string]PathStatus, len(paths))
	scmpH := scmpHandler{mtx: &sync.Mutex{}, statuses: pathStatuses}
	network := snet.NewCustomNetworkWithPR(p.Local.IA,
		&snet.DefaultPacketDispatcherService{
			Dispatcher:  reliable.NewDispatcherService(""),
			SCMPHandler: scmpH,
		},
		nil,
	)
	if err := snet.InitWithNetwork(network); err != nil {
		return nil, common.NewBasicError("failed to initialize SNET", err)
	}
	snetConn, err := snet.ListenSCION("udp4", &p.Local)
	if err != nil {
		return nil, common.NewBasicError("listening failed", err)
	}
	scionConn := snetConn.(*snet.SCIONConn)
	err = scionConn.SetReadDeadline(deadline)
	if err != nil {
		return nil, common.NewBasicError("failed to set deadline", err)
	}
	for _, path := range paths {
		scmpH.setStatus(string(path.Path.FwdPath), Timeout)
		p.sendTestPacket(scionConn, path)
	}
	for i := len(scmpH.statuses); i > 0; i-- {
		err := p.receiveTestReply(scionConn)
		if err != nil {
			return nil, err
		}
	}
	return scmpH.statuses, nil
}

func (p PathProber) sendTestPacket(scionConn *snet.SCIONConn, path sciond.PathReplyEntry) error {
	sPath := spath.New(path.Path.FwdPath)
	if err := sPath.InitOffsets(); err != nil {
		return common.NewBasicError("unable to initialize path", err)
	}
	nextHop, err := path.HostInfo.Overlay()
	if err != nil {
		return common.NewBasicError("unable to get overlay info", err)
	}
	addr := &snet.Addr{
		IA: p.DstIA,
		Host: &addr.AppAddr{
			L3: addr.HostSVCFromString("NONE"),
			L4: addr.NewL4UDPInfo(0),
		},
		NextHop: nextHop,
		Path:    sPath,
	}
	log.Debug("Sending test packet.", "path", path.Path.String())
	_, err = scionConn.WriteTo([]byte{}, addr)
	if err != nil {
		return common.NewBasicError("cannot send packet", err)
	}
	return nil
}

func (p PathProber) receiveTestReply(scionConn *snet.SCIONConn) error {
	b := make([]byte, 1500, 1500)
	_, _, err := scionConn.ReadFromSCION(b)
	if err == nil {
		// We've got an actual reply instead of SCMP error. This should not happen.
		return nil
	}
	if xerrors.Is(err, errBadHost) || xerrors.Is(err, errSCMP) {
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
	mtx      *sync.Mutex
	statuses map[string]PathStatus
}

func (h scmpHandler) Handle(pkt *snet.SCIONPacket) error {
	hdr, ok := pkt.L4Header.(*scmp.Hdr)
	if ok {
		path, err := h.path(pkt)
		if err != nil {
			return err
		}
		if hdr.Class == scmp.C_Routing && hdr.Type == scmp.T_R_BadHost {
			h.setStatus(path, Alive)
			return errBadHost
		}
		h.setStatus(path, PathStatus{status: statusSCMP, additionalInfo: hdr.String()})
		return errSCMP
	}
	return nil
}

func (h scmpHandler) path(pkt *snet.SCIONPacket) (string, error) {
	path := pkt.Path.Copy()
	if err := path.Reverse(); err != nil {
		return "", common.NewBasicError("unable to reverse path on received packet", err)
	}
	return string(path.Raw), nil
}

func (h scmpHandler) setStatus(path string, status PathStatus) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	h.statuses[path] = status
}
