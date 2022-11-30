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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/sock/reliable"
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
	dp := path.Dataplane()
	switch p := dp.(type) {
	case snetpath.SCION:
		return string(p.Raw)
	case *snetpath.EPIC:
		return string(p.SCION)
	}
	return ""
}

// FilterEmptyPaths removes all empty paths from paths and returns a copy.
func FilterEmptyPaths(paths []snet.Path) []snet.Path {
	if paths == nil {
		return nil
	}
	filtered := make([]snet.Path, 0, len(paths))
	for _, path := range paths {
		if _, isEmpty := path.Dataplane().(snetpath.Empty); !isEmpty {
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
	// Dispatcher is the path to the dispatcher socket. Leaving this empty uses
	// the default dispatcher socket value.
	Dispatcher string
	// Metrics injected into snet.DefaultPacketDispatcherService.
	SCIONPacketConnMetrics snet.SCIONPacketConnMetrics
}

type options struct {
	epic bool
}

type Option func(o *options)

func applyOption(opts []Option) options {
	var o options
	for _, option := range opts {
		option(&o)
	}
	return o
}

func WithEPIC(epic bool) Option {
	return func(o *options) {
		o.epic = epic
	}
}

// GetStatuses probes the paths and returns the statuses of the paths. The
// returned map is keyed with path.Path.FwdPath. The input should only be
// non-empty paths.
func (p Prober) GetStatuses(ctx context.Context, paths []snet.Path,
	opts ...Option) (map[string]Status, error) {

	o := applyOption(opts)
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, serrors.New("deadline required on ctx")
	}

	for _, path := range paths {
		if _, ok := path.Dataplane().(snetpath.SCION); !ok {
			return nil, serrors.New("paths must be of type SCION",
				"path", common.TypeOf(path.Dataplane()))
		}
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
		Dispatcher:             reliable.NewDispatcher(p.Dispatcher),
		SCMPHandler:            &scmpHandler{},
		SCIONPacketConnMetrics: p.SCIONPacketConnMetrics,
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
			if err := conn.SetDeadline(deadline); err != nil {
				return serrors.WrapStr("setting deadline", err)
			}

			// Send probe for each path.
			for _, path := range paths {
				originalPath, ok := path.Dataplane().(snetpath.SCION)
				if !ok {
					return serrors.New("not a scion path")
				}

				scionAlertPath, err := setAlertFlag(originalPath)
				if err != nil {
					return serrors.WrapStr("setting alert flag", err)
				}
				var alertPath snet.DataplanePath
				if o.epic {
					epicAlertPath, err := snetpath.NewEPICDataplanePath(
						scionAlertPath,
						path.Metadata().EpicAuths,
					)
					if err != nil {
						return err
					}
					alertPath = epicAlertPath
				} else {
					alertPath = scionAlertPath
				}

				pkt := &snet.Packet{
					PacketInfo: snet.PacketInfo{
						Destination: snet.SCIONAddress{
							IA:   p.DstIA,
							Host: addr.SvcNone,
						},
						Source: snet.SCIONAddress{
							IA:   p.LocalIA,
							Host: addr.HostFromIP(localIP),
						},
						Path: alertPath,
						Payload: snet.SCMPTracerouteRequest{
							Identifier: p.ID,
							Sequence:   uint16(atomic.AddInt32(&seq, 1)),
						},
					},
				}
				if err := conn.WriteTo(pkt, path.UnderlayNextHop()); err != nil {
					return err
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

type reply struct {
	Status  Status
	PathKey string
}

func (r reply) Error() string {
	return fmt.Sprint(r.Status)
}

type scmpHandler struct{}

func (h *scmpHandler) Handle(pkt *snet.Packet) error {
	path, ok := pkt.Path.(snet.RawPath)
	if !ok {
		return serrors.New("not an snet.RawPath")
	}
	replyPath, err := snet.DefaultReplyPather{}.ReplyPath(path)
	if err != nil {
		return serrors.WrapStr("creating reply path", err)
	}
	rawReplyPath, ok := replyPath.(snet.RawReplyPath)
	if !ok {
		return serrors.New("not an snet.RawReplyPath", "type", common.TypeOf(replyPath))
	}
	scionReplyPath := snetpath.SCION{
		Raw: make([]byte, rawReplyPath.Path.Len()),
	}
	if err := rawReplyPath.Path.SerializeTo(scionReplyPath.Raw); err != nil {
		return serrors.WrapStr("serialization failed", err)
	}
	status, err := h.toStatus(pkt)
	if err != nil {
		return err
	}
	return reply{
		Status:  status,
		PathKey: PathKey(snetpath.Path{DataplanePath: scionReplyPath}),
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

func setAlertFlag(original snetpath.SCION) (snetpath.SCION, error) {
	var decoded scion.Decoded
	if err := decoded.DecodeFromBytes(original.Raw); err != nil {
		return snetpath.SCION{}, serrors.WrapStr("decoding path", err)
	}
	if len(decoded.InfoFields) > 0 {
		info := decoded.InfoFields[len(decoded.InfoFields)-1]
		if info.ConsDir {
			decoded.HopFields[len(decoded.HopFields)-1].IngressRouterAlert = true
		} else {
			decoded.HopFields[len(decoded.HopFields)-1].EgressRouterAlert = true
		}
	}
	return snetpath.NewSCIONFromDecoded(decoded)
}
