// Copyright 2023 ETH Zurich
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

package dispatcher

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/topology"
)

const ErrUnsupportedL4 common.ErrMsg = "unsupported SCION L4 protocol"

// Server is the main object allowing to forward SCION packets coming
// from legacy BR to the final endhost application and to handle SCMP
// info packets destined to this endhost.
type Server struct {
	conn *net.UDPConn
	// topo keeps the topology for the local AS. It can keep multiple ASes
	// in case we run several topologies locally, e.g., developer environment.

	// TODO(JordiSubira): This may be taken from daemon for non self-contained
	// applications.
	topo      map[addr.AS]*topology.Loader
	buf       []byte
	oobuf     []byte
	outBuffer gopacket.SerializeBuffer
	decoded   []gopacket.LayerType
	parser    *gopacket.DecodingLayerParser
	options   gopacket.SerializeOptions

	scionLayer slayers.SCION
	hbh        slayers.HopByHopExtnSkipper
	e2e        slayers.EndToEndExtn
	udpLayer   slayers.UDP
	scmpLayer  slayers.SCMP
}

// NewServer creates new instance of Server.
func NewServer(topo map[addr.AS]*topology.Loader, conn *net.UDPConn) *Server {
	server := Server{
		topo:      topo,
		conn:      setIPPktInfo(conn),
		buf:       make([]byte, common.SupportedMTU),
		oobuf:     make([]byte, 1024),
		decoded:   make([]gopacket.LayerType, 4),
		outBuffer: gopacket.NewSerializeBuffer(),
		options: gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
	}
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION,
		&server.scionLayer,
		&server.hbh,
		&server.e2e,
		&server.udpLayer,
		&server.scmpLayer,
	)
	parser.IgnoreUnsupported = true
	server.parser = parser
	server.scionLayer.RecyclePaths()
	server.udpLayer.SetNetworkLayerForChecksum(&server.scionLayer)
	server.scmpLayer.SetNetworkLayerForChecksum(&server.scionLayer)
	return &server
}

// Serve starts reading packets from network and dispatching them to the end application.
// It also replies to SCMPEchoRequest and SCMPTracerouteRequest.
// The function blocks and returns if there's an error or when Close has been called.
func (s *Server) Serve() error {
	for {
		s.buf = s.buf[:cap(s.buf)]

		n, nn, _, previousHop, err := s.conn.ReadMsgUDPAddrPort(s.buf, s.oobuf)
		if err != nil {
			log.Error("Reading message", "err", err)
			continue
		}

		nextHopAddr, err := s.processMsgNextHop(s.buf[:n], previousHop)
		if err != nil {
			return err
		}
		if nextHopAddr == nil {
			// some error parsing the address from the incoming packet;
			// we discard the packet and keep serving.
			continue
		}

		// If the outgoing message is SCMP Informational message (Echo or Traceroute)
		// the dispatcher has already processed the response, and the nextHop address
		// belongs to the BR.
		isSCMPinfo := s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeTracerouteReply ||
			s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeEchoReply
		if isSCMPinfo || s.validateNextHopAddr(*nextHopAddr, s.oobuf[:nn]) {
			m, err := s.conn.WriteToUDPAddrPort(s.outBuffer.Bytes(), *nextHopAddr)
			if err != nil || m != len(s.outBuffer.Bytes()) {
				log.Error("writing packet out", "err", err)
			}
		}
	}
}

// processMsgNextHop processes the message arriving to the shim dispatcher and serializes
// the outbound packet into buf. The intended nextHop address, either the end application,
// or the next BR (for SCMP informational response) is returned. It returns a non-nil error
// for non-recoverable errors, only. If the incoming packet couldn't be processed due to a
// recoverable error, the returned address will be nil. The caller must check both values
// consistently.
func (s *Server) processMsgNextHop(buf []byte, prevHop netip.AddrPort) (*netip.AddrPort, error) {
	err := s.parser.DecodeLayers(buf, &s.decoded)
	if err != nil {
		log.Error("Decoding layers", "err", err)
		return nil, nil
	}
	if len(s.decoded) < 2 {
		log.Error("Unexpected decode packet", "layers decoded", len(s.decoded))
		return nil, nil
	}
	err = s.outBuffer.Clear()
	if err != nil {
		return nil, err
	}
	// Packet handling
	var dstAddrPort netip.AddrPort
	switch s.decoded[len(s.decoded)-1] {
	case slayers.LayerTypeSCMP:
		// send response to BR
		if s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeTracerouteRequest ||
			s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeEchoRequest {
			err = s.reverseSCMPInfo()
			if err != nil {
				log.Error("Reversing SCMP information", "err", err)
				return nil, nil
			}
			dstAddrPort = prevHop
		} else { // relay to end application
			dstAddrPort, err = s.getDstSCMP()
			if err != nil {
				log.Error("Getting destination for SCMP message", "err", err)
				return nil, nil
			}
		}
		payload := gopacket.Payload(s.scmpLayer.Payload)
		err = payload.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing payload", "err", err)
			return nil, nil
		}
		s.outBuffer.PushLayer(payload.LayerType())

		err = s.scmpLayer.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing SCMP header", "err", err)
			return nil, nil
		}
		s.outBuffer.PushLayer(s.scmpLayer.LayerType())
	case slayers.LayerTypeSCIONUDP:
		dstAddrPort, err = s.getDstSCIONUDP()
		if err != nil {
			log.Error("Getting destination for SCION/UDP message", "err", err)
			return nil, nil
		}
		payload := gopacket.Payload(s.udpLayer.Payload)
		err = payload.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing payload", "err", err)
			return nil, nil
		}
		s.outBuffer.PushLayer(payload.LayerType())

		err = s.udpLayer.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing udp header", "err", err)
			return nil, nil
		}
		s.outBuffer.PushLayer(s.udpLayer.LayerType())
	}
	if s.decoded[len(s.decoded)-2] == slayers.LayerTypeEndToEndExtn {
		err = s.e2e.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing e2e extension", "err", err)
			return nil, nil
		}
		s.outBuffer.PushLayer(s.e2e.LayerType())
	}
	err = s.scionLayer.SerializeTo(s.outBuffer, s.options)
	if err != nil {
		log.Error("Serializing SCION header", "err", err)
		return nil, nil
	}
	s.outBuffer.PushLayer(s.scionLayer.LayerType())

	return &dstAddrPort, nil
}

func (s *Server) reverseSCMPInfo() error {
	// Translate request to a reply.
	switch s.scmpLayer.NextLayerType() {
	case slayers.LayerTypeSCMPEcho:
		s.scmpLayer.TypeCode = slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0)
	case slayers.LayerTypeSCMPTraceroute:
		s.scmpLayer.TypeCode = slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0)
	default:
		return serrors.New("unsupported SCMP informational message")
	}
	if err := s.reverseSCION(); err != nil {
		return err
	}
	// XXX(roosd): This does not take HBH and E2E extensions into consideration.
	// See: https://github.com/scionproto/scion/issues/4128
	// TODO(JordiSubira): Add support for SPAO-E2E
	s.scionLayer.NextHdr = slayers.L4SCMP
	return nil
}

func (s *Server) reverseSCION() error {
	// Reverse the SCION packet.
	s.scionLayer.DstIA, s.scionLayer.SrcIA = s.scionLayer.SrcIA, s.scionLayer.DstIA
	src, err := s.scionLayer.SrcAddr()
	if err != nil {
		return serrors.WrapStr("parsing source address", err)
	}
	dst, err := s.scionLayer.DstAddr()
	if err != nil {
		return serrors.WrapStr("parsing destination address", err)
	}
	if err := s.scionLayer.SetSrcAddr(dst); err != nil {
		return serrors.WrapStr("setting source address", err)
	}
	if err := s.scionLayer.SetDstAddr(src); err != nil {
		return serrors.WrapStr("setting destination address", err)
	}
	if s.scionLayer.PathType == epic.PathType {
		// Received packet with EPIC path type, hence extract the SCION path
		epicPath, ok := s.scionLayer.Path.(*epic.Path)
		if !ok {
			return serrors.New("path type and path data do not match")
		}
		s.scionLayer.Path = epicPath.ScionPath
		s.scionLayer.PathType = scion.PathType
	}
	if s.scionLayer.Path, err = s.scionLayer.Path.Reverse(); err != nil {
		return serrors.WrapStr("reversing path", err)
	}
	return nil
}

func (s *Server) getDstSCMP() (netip.AddrPort, error) {
	// Check if its SCMPEcho or SCMPTraceroute reply
	if s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeEchoReply {
		var scmpEcho slayers.SCMPEcho
		err := scmpEcho.DecodeFromBytes(s.scmpLayer.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return addrPortFromBytes(s.scionLayer.RawDstAddr, scmpEcho.Identifier)
	}
	if s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeTracerouteReply {
		var scmpTraceroute slayers.SCMPTraceroute
		err := scmpTraceroute.DecodeFromBytes(s.scmpLayer.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return addrPortFromBytes(s.scionLayer.RawDstAddr, scmpTraceroute.Identifier)
	}

	// Drop unknown SCMP error messages.
	if s.scmpLayer.NextLayerType() == gopacket.LayerTypePayload {
		return netip.AddrPort{}, serrors.New("unsupported SCMP error message",
			"type", s.scmpLayer.TypeCode.Type())
	}
	l, err := decodeSCMP(&s.scmpLayer)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(l) != 2 {
		return netip.AddrPort{}, serrors.New("SCMP error message without payload")
	}
	gpkt := gopacket.NewPacket(*l[1].(*gopacket.Payload), slayers.LayerTypeSCION,
		gopacket.DecodeOptions{
			NoCopy: true,
		},
	)

	// If the offending packet was UDP/SCION, use the source port to deliver.
	if udp := gpkt.Layer(slayers.LayerTypeSCIONUDP); udp != nil {
		port := udp.(*slayers.UDP).SrcPort
		// XXX(roosd): We assume that the zero value means the UDP header is
		// truncated. This flags packets of misbehaving senders as truncated, if
		// they set the source port to 0. But there is no harm, since those
		// packets are destined to be dropped anyway.
		if port == 0 {
			return netip.AddrPort{}, serrors.New("SCMP error with truncated UDP header")
		}
		return addrPortFromBytes(s.scionLayer.RawDstAddr, port)
	}

	// If the offending packet was SCMP/SCION, and it is an echo or traceroute,
	// use the Identifier to deliver. In all other cases, the message is dropped.
	if scmp := gpkt.Layer(slayers.LayerTypeSCMP); scmp != nil {

		tc := scmp.(*slayers.SCMP).TypeCode
		// SCMP Error messages in response to an SCMP error message are not allowed.
		if !tc.InfoMsg() {
			return netip.AddrPort{},
				serrors.New("SCMP error message in response to SCMP error message",
					"type", tc.Type())
		}
		// We only support echo and traceroute requests.
		t := tc.Type()
		if t != slayers.SCMPTypeEchoRequest && t != slayers.SCMPTypeTracerouteRequest {
			return netip.AddrPort{}, serrors.New("unsupported SCMP info message", "type", t)
		}

		var port uint16
		// Extract the port from the echo or traceroute ID field.
		if echo := gpkt.Layer(slayers.LayerTypeSCMPEcho); echo != nil {
			port = echo.(*slayers.SCMPEcho).Identifier
		} else if tr := gpkt.Layer(slayers.LayerTypeSCMPTraceroute); tr != nil {
			port = tr.(*slayers.SCMPTraceroute).Identifier
		} else {
			return netip.AddrPort{}, serrors.New("SCMP error with truncated payload")
		}
		return addrPortFromBytes(s.scionLayer.RawDstAddr, port)
	}
	return netip.AddrPort{}, ErrUnsupportedL4
}

func (s *Server) getDstSCIONUDP() (netip.AddrPort, error) {
	host, err := s.scionLayer.DstAddr()
	if err != nil {
		return netip.AddrPort{}, err
	}
	switch host.Type() {
	case addr.HostTypeSVC:
		topo, ok := s.topo[s.scionLayer.DstIA.AS()]
		if !ok {
			return netip.AddrPort{}, serrors.New("SVC destination not found",
				"IA", s.scionLayer.DstIA)
		}
		udpAddr, err := topo.GetUnderlay(host.SVC())
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(udpAddr.AddrPort().Addr(), udpAddr.AddrPort().Port()), nil
	case addr.HostTypeIP:
		return addrPortFromBytes(s.scionLayer.RawDstAddr, s.udpLayer.DstPort)
	default:
		return netip.AddrPort{}, serrors.New("Invalid host type", "type", host.Type().String())
	}
}

type controlMessage interface {
	Destination() net.IP
	Parse(b []byte) error
	String() string
}

type ipv4ControlMessage struct {
	*ipv4.ControlMessage
}

func (m ipv4ControlMessage) Destination() net.IP {
	return m.Dst
}

type ipv6ControlMessage struct {
	*ipv6.ControlMessage
}

func (m ipv6ControlMessage) Destination() net.IP {
	return m.Dst
}

// validateNextHopAddr returnS true if the underlay address on the UDP/IP wrapper
// header corresponds to the address on the encapsulated UDP/SCION header, otherwise
// it returns false. This implements a safeguard for traffic reflection as discussed in:
// https://github.com/scionproto/scion/pull/4280#issuecomment-1775177351
func (s *Server) validateNextHopAddr(addr netip.AddrPort, oobuffer []byte) bool {
	// take localAddr to be consistent with the setIPPktInfo(·) configuration
	localAddr, ok := s.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		panic(fmt.Sprintln("Connection address is not UDPAddr",
			"conn", s.conn.LocalAddr().Network()))
	}

	var cm controlMessage
	if localAddr.AddrPort().Addr().Unmap().Is4() {
		cm = ipv4ControlMessage{
			ControlMessage: new(ipv4.ControlMessage),
		}
	}
	if localAddr.AddrPort().Addr().Unmap().Is6() {
		cm = ipv6ControlMessage{
			ControlMessage: new(ipv6.ControlMessage),
		}
	}

	if err := cm.Parse(oobuffer); err != nil {
		log.Error("Parsing message", "err", err)
		return false
	}
	if !cm.Destination().IsUnspecified() {
		pktAddr, ok := netip.AddrFromSlice(cm.Destination())
		if !ok {
			log.Error("Getting DST from IP_PKT info", "DST", cm.Destination())
			return false
		}
		if addr.Addr().Unmap().Compare(pktAddr.Unmap()) != 0 {
			log.Error("UDP/IP addr destination different from UDP/SCION addr",
				"UDP/IP:", pktAddr.String(),
				"UDP/SCION:", addr.Addr().String())
			return false
		}
		return true
	}
	log.Error("Unable to validate next hop address", "addr", addr)
	return false
}

func ListenAndServe(topo map[addr.AS]*topology.Loader, addr *net.UDPAddr) error {
	conn, err := net.ListenUDP(addr.Network(), addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Debug(fmt.Sprintf("local address: %s", conn.LocalAddr()))
	dispServer := NewServer(topo, conn)

	errChan := make(chan error)
	go func() {
		defer log.HandlePanic()
		errChan <- dispServer.Serve()
	}()

	return <-errChan
}

// decodeSCMP decodes the SCMP payload. WARNING: Decoding is done with NoCopy set.
func decodeSCMP(scmp *slayers.SCMP) ([]gopacket.SerializableLayer, error) {
	gpkt := gopacket.NewPacket(scmp.Payload, scmp.NextLayerType(),
		gopacket.DecodeOptions{NoCopy: true})
	layers := gpkt.Layers()
	if len(layers) == 0 || len(layers) > 2 {
		return nil, serrors.New("invalid number of SCMP layers", "count", len(layers))
	}
	ret := make([]gopacket.SerializableLayer, len(layers))
	for i, l := range layers {
		s, ok := l.(gopacket.SerializableLayer)
		if !ok {
			return nil, serrors.New("invalid SCMP layer, not serializable", "index", i)
		}
		ret[i] = s
	}
	return ret, nil
}

func addrPortFromBytes(addr []byte, port uint16) (netip.AddrPort, error) {
	a, ok := netip.AddrFromSlice(addr)
	if !ok {
		return netip.AddrPort{}, serrors.New("Unexpected raw address byte slice format")
	}
	return netip.AddrPortFrom(a, port), nil
}

func setIPPktInfo(conn *net.UDPConn) *net.UDPConn {
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		panic(fmt.Sprintln("Connection address is not UDPAddr",
			"conn", conn.LocalAddr().Network()))
	}

	if udpAddr.AddrPort().Addr().Unmap().Is4() {
		err := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
		if err != nil {
			panic(fmt.Sprintf("cannot set IP_PKTINFO on socket: %s", err))
		}
	}
	if udpAddr.AddrPort().Addr().Unmap().Is6() {
		err := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
		if err != nil {
			panic(fmt.Sprintf("cannot set IP_PKTINFO on socket: %s", err))
		}
	}

	return conn
}
