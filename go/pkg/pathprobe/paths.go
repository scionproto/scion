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
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
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
	LocalIP        net.IP
	AdditionalInfo string
}

func (s Status) String() string {
	if s.AdditionalInfo == "" {
		return string(s.Status)
	}
	return fmt.Sprintf("%s(%s)", s.Status, s.AdditionalInfo)
}

// PathKey is the mapping of a path reply entry to a key that is returned in
// GetStatuses.
func PathKey(path snet.Path) string {
	spath := path.Path()
	if spath.IsEmpty() {
		return ""
	}
	return string(spath.Raw)
}

// FilterEmptyPaths removes all empty paths from paths and returns a copy.
func FilterEmptyPaths(paths []snet.Path) []snet.Path {
	if paths == nil {
		return nil
	}
	filtered := make([]snet.Path, 0, len(paths))
	for _, path := range paths {
		if !path.Path().IsEmpty() && len(path.Path().Raw) > 0 {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

// Prober can be used to get the status of a path.
type Prober struct {
	// DstIA is the destination ISD-AS.
	DstIA addr.IA
	// LocalIA is the source ISD-AS.
	LocalIA addr.IA
	// LocalIP is the local IP endpoint to be used when probing. If not set, the proper will resolve
	// an appropriate local IP endpoint depending on the path that should be probed. Note, LocalIP
	// should not be set, unless you know what you are doing.
	LocalIP net.IP
	// ID is the SCMP traceroute ID used by the Prober.
	ID uint16
}

// GetStatuses probes the paths and returns the statuses of the paths. The
// returned map is keyed with path.Path.FwdPath. The input should only be
// non-empty paths.
func (p Prober) GetStatuses(ctx context.Context, paths []snet.Path) (map[string]Status, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, serrors.New("deadline required on ctx")
	}

	// Check whether paths are alive. This is done by sending a traceroute
	// request for the last interface of the path.
	// Receiving the traceroute response means that the path is alive.

	var statusesLock sync.Mutex
	statuses := make(map[string]Status, len(paths))
	addStatus := func(key string, status Status) {
		statusesLock.Lock()
		defer statusesLock.Unlock()
		statuses[key] = status
	}

	// Instantiate dispatcher service
	disp := &snet.DefaultPacketDispatcherService{
		Dispatcher:  reliable.NewDispatcher(""),
		SCMPHandler: &scmpHandler{},
	}

	// Resolve all the local IPs per path. We will open one connection
	// per local IP address.
	pathsPerIP := map[string][]snet.Path{}
	for _, path := range paths {
		localIP, err := p.resolveLocalIP(path.UnderlayNextHop())
		if err != nil {
			addStatus(
				PathKey(path),
				Status{
					Status:         StatusUnknown,
					AdditionalInfo: fmt.Sprintf("Failed to resolve local IP: %s", err),
				},
			)
			continue
		}
		pathsPerIP[localIP.String()] = append(pathsPerIP[localIP.String()], path)
		addStatus(PathKey(path), Status{Status: StatusTimeout, LocalIP: localIP})
	}

	// Sequence number for the sent traceroute packets.
	var seq int32
	g, _ := errgroup.WithContext(ctx)
	for ip, paths := range pathsPerIP {
		ip, paths := ip, paths
		g.Go(func() error {
			defer log.HandlePanic()

			localIP := net.ParseIP(ip)
			conn, _, err := disp.Register(ctx, p.LocalIA, &net.UDPAddr{IP: localIP}, addr.SvcNone)
			if err != nil {
				return serrors.WrapStr("creating packet conn", err, "local", localIP)
			}
			defer conn.Close()
			conn.SetDeadline(deadline)

			// Send probe for each path.
			for _, path := range paths {
				seqNr := atomic.AddInt32(&seq, 1)
				localAddr := snet.SCIONAddress{
					IA:   p.LocalIA,
					Host: addr.HostFromIP(localIP),
				}
				if err := p.sendProbe(conn, localAddr, path, uint16(seqNr)); err != nil {
					return serrors.WrapStr("sending probe", err, "local", localIP)
				}
			}

			// Wait for the replies.
			var pkt snet.Packet
			var ov net.UDPAddr
			for range paths {
				if err := conn.ReadFrom(&pkt, &ov); err != nil {
					var r reply
					if errors.As(err, &r) {
						addStatus(r.PathKey, r.Status)
						continue
					}
					// If the deadline is exceeded, all remaining paths have timed out.
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					return serrors.WrapStr("waiting for probe reply", err, "local", localIP)
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return statuses, nil
}

func (p Prober) resolveLocalIP(target *net.UDPAddr) (net.IP, error) {
	if p.LocalIP != nil {
		return p.LocalIP, nil
	}
	if target == nil {
		return nil, serrors.New("underlay nexthop missing")
	}
	localIP, err := addrutil.ResolveLocal(target.IP)
	if err != nil {
		return nil, serrors.WrapStr("resolving local IP", err)
	}
	return localIP, nil
}

func (p Prober) sendProbe(
	scionConn snet.PacketConn,
	localAddr snet.SCIONAddress,
	path snet.Path,
	nextSeq uint16,
) error {
	alertingPath := path.Path()
	if err := setAlertFlag(&alertingPath, true); err != nil {
		return err
	}
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   p.DstIA,
				Host: addr.SvcNone,
			},
			Source: localAddr,
			Path:   alertingPath,
			Payload: snet.SCMPTracerouteRequest{
				Identifier: p.ID,
				Sequence:   nextSeq,
			},
		},
	}
	return scionConn.WriteTo(pkt, path.UnderlayNextHop())
}

type reply struct {
	Status  Status
	PathKey string
}

func (r reply) Error() string {
	return fmt.Sprint(r.Status)
}

type scmpHandler struct{}

func (h *scmpHandler) Handle(pkt *snet.Packet) error {
	// XXX(hendrikzuellig): This modifies the packet's path.
	// We do not care because the packet is discarded anyway.
	reversePath := pkt.Path
	reversePath.Reverse()
	if err := setAlertFlag(&reversePath, false); err != nil {
		return err
	}
	status, err := h.toStatus(pkt)
	if err != nil {
		return err
	}
	return reply{
		Status:  status,
		PathKey: string(reversePath.Raw),
	}
}

func (h *scmpHandler) toStatus(pkt *snet.Packet) (Status, error) {
	if pkt.Payload == nil {
		return Status{}, serrors.New("no payload found")
	}
	localIP := pkt.Destination.Host.IP()
	switch pld := pkt.Payload.(type) {
	case snet.SCMPTracerouteReply:
		return Status{Status: StatusAlive, LocalIP: localIP}, nil
	case snet.SCMPExternalInterfaceDown:
		return Status{
			Status:  StatusSCMP,
			LocalIP: localIP,
			AdditionalInfo: fmt.Sprintf("external interface down: isd_as=%s interface=%d",
				pld.IA, pld.Interface),
		}, nil
	case snet.SCMPInternalConnectivityDown:
		return Status{
			Status:  StatusSCMP,
			LocalIP: localIP,
			AdditionalInfo: fmt.Sprintf("internal connectivity down: "+
				"isd_as=%s ingress=%d egress=%d", pld.IA, pld.Ingress, pld.Egress),
		}, nil
	default:
		return Status{
			Status:         StatusUnknown,
			LocalIP:        localIP,
			AdditionalInfo: fmt.Sprintf("unknown payload type: (%T)", pld),
		}, nil
	}
}

func setAlertFlag(path *spath.Path, flag bool) error {
	decodedPath := scion.Decoded{}
	if err := decodedPath.DecodeFromBytes((*path).Raw); err != nil {
		return serrors.WrapStr("decoding path", err)
	}
	if len(decodedPath.InfoFields) > 0 {
		infoF := decodedPath.InfoFields[len(decodedPath.InfoFields)-1]
		if infoF.ConsDir {
			decodedPath.HopFields[len(decodedPath.HopFields)-1].IngressRouterAlert = flag
		} else {
			decodedPath.HopFields[len(decodedPath.HopFields)-1].EgressRouterAlert = flag
		}
	}
	if err := decodedPath.SerializeTo((*path).Raw); err != nil {
		return serrors.WrapStr("serializing path", err)
	}
	return nil
}
