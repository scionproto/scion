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

	"github.com/gopacket/gopacket"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const ErrUnsupportedL4 common.ErrMsg = "unsupported SCION L4 protocol"

// Server is the main object allowing to forward SCION packets coming
// from legacy BR to the final endhost application and to handle SCMP
// info packets destined to this endhost.
type Server struct {
	// isDispatcher indicates whether the shim acts as SCION packet
	// dispatcher
	isDispatcher bool
	conn         *net.UDPConn
	// topo keeps the topology for the local AS. It can keep multiple ASes
	// in case we run several topologies locally, e.g., developer environment.

	// TODO(JordiSubira): This may be taken from daemon for non self-contained
	// applications.
	ServiceAddresses map[addr.Addr]netip.AddrPort
	buf              []byte
	oobuf            []byte
	outBuffer        gopacket.SerializeBuffer
	decoded          []gopacket.LayerType
	parser           *gopacket.DecodingLayerParser
	cmParser         controlMessageParser
	options          gopacket.SerializeOptions

	scionLayer slayers.SCION
	hbh        slayers.HopByHopExtnSkipper
	e2e        slayers.EndToEndExtn
	udpLayer   slayers.UDP
	scmpLayer  slayers.SCMP
}

// NewServer creates new instance of Server.
func NewServer(
	isDispatcher bool,
	svcAddrs map[addr.Addr]netip.AddrPort,
	conn *net.UDPConn,
) *Server {
	server := Server{
		isDispatcher:     isDispatcher,
		ServiceAddresses: svcAddrs,
		buf:              make([]byte, common.SupportedMTU),
		oobuf:            make([]byte, 1024),
		decoded:          make([]gopacket.LayerType, 4),
		outBuffer:        gopacket.NewSerializeBuffer(),
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
	server.conn = conn
	if isDispatcher {
		server.conn, server.cmParser = setIPPktInfo(conn)
	}
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
		n, nn, _, prevHop, err := s.conn.ReadMsgUDPAddrPort(s.buf, s.oobuf)
		if err != nil {
			log.Error("Reading message", "err", err)
			continue
		}

		var underlay netip.Addr
		if s.isDispatcher {
			underlay = s.parseUnderlayAddr(s.oobuf[:nn])
			if !underlay.IsValid() {
				// some error parsing the CM info from the incoming packet;
				// we discard the packet and keep serving.
				continue
			}
		}

		outBuf, nextHopAddr, err := s.processMsgNextHop(s.buf[:n], underlay, prevHop)
		if err != nil {
			return err
		}
		if !nextHopAddr.IsValid() {
			// some error processing the incoming packet;
			// we discard the packet and keep serving.
			continue
		}

		m, err := s.conn.WriteToUDPAddrPort(outBuf, nextHopAddr)
		if err != nil {
			log.Error("writing packet out", "err", err)
			continue
		}
		if m != len(outBuf) {
			log.Error("writing packet out", "message len", len(outBuf), "written bytes", n)
		}
	}
}

// processMsgNextHop processes the message arriving at the shim dispatcher and returns
// a byte array corresponding to the packet that needs to be forwarded.
// The input byte array `buf` is the raw incoming packet;
// `underlay` corresponds to the IP address on the outer UDP/IP header;
// `prevHop` is the address from the previous SCION hop in the local network.
// The intended nextHop address, i.e., either the end application
// or the next BR (for SCMP informational response), is returned.
// It returns a non-nil error for non-recoverable errors only.
// If the incoming packet couldn't be processed due to a recoverable error or
// incorrect address validation, the returned buffer will be nil and the address
// will be empty.
// The caller must consistently check both values.
func (s *Server) processMsgNextHop(
	buf []byte,
	underlay netip.Addr,
	prevHop netip.AddrPort,
) ([]byte, netip.AddrPort, error) {

	err := s.parser.DecodeLayers(buf, &s.decoded)
	if err != nil {
		log.Error("Decoding layers", "err", err)
		return nil, netip.AddrPort{}, nil
	}
	if len(s.decoded) < 2 {
		log.Error("Unexpected packet", "layers decoded", len(s.decoded))
		return nil, netip.AddrPort{}, nil
	}
	err = s.outBuffer.Clear()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	// If the dispatcher feature flag is disabled we only process SCMPInfo packets.
	if !s.isDispatcher {
		if s.decoded[len(s.decoded)-1] != slayers.LayerTypeSCMP {
			log.Debug("Dispatcher feature is disabled, shim discards non-SCMPInfo packets",
				"received", s.decoded[len(s.decoded)-1])
			return nil, netip.AddrPort{}, nil
		}
		if s.scmpLayer.TypeCode.Type() != slayers.SCMPTypeTracerouteRequest &&
			s.scmpLayer.TypeCode.Type() != slayers.SCMPTypeEchoRequest {
			log.Debug("Dispatcher feature is disabled, shim discards non-SCMPInfo packets",
				"received", s.scmpLayer.TypeCode.Type())
			return nil, netip.AddrPort{}, nil
		}
	}

	var dstAddrPort netip.AddrPort
	// Retrieve DST UDP/SCION addr and compare to underlay address if it applies,
	// i.e., all cases expect SCMPInfo request messages, which are to be replied
	// by the shim dispatcher itself.
	switch s.decoded[len(s.decoded)-1] {
	case slayers.LayerTypeSCMP:
		// send response to BR
		if s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeTracerouteRequest ||
			s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeEchoRequest {
			dstAddrPort = prevHop
		} else { // relay to end application
			dstAddrPort, err = s.getDstSCMP()
			if err != nil {
				log.Error("Getting destination for SCMP message", "err", err)
				return nil, netip.AddrPort{}, nil
			}
			if dstAddrPort.Addr().Unmap().Compare(underlay.Unmap()) != 0 {
				log.Error("UDP/IP addr destination different from UDP/SCION addr",
					"UDP/IP:", underlay.Unmap().String(),
					"UDP/SCION:", dstAddrPort.Addr().Unmap().String())
				return nil, netip.AddrPort{}, nil
			}
		}
	case slayers.LayerTypeSCIONUDP:
		dstAddrPort, err = s.getDstSCIONUDP()
		if err != nil {
			log.Error("Getting destination for SCION/UDP message", "err", err)
			return nil, netip.AddrPort{}, nil
		}
		if dstAddrPort.Addr().Unmap().Compare(underlay.Unmap()) != 0 {
			log.Error("UDP/IP addr destination different from UDP/SCION addr",
				"UDP/IP:", underlay.Unmap().String(),
				"UDP/SCION:", dstAddrPort.Addr().Unmap().String())
			return nil, netip.AddrPort{}, nil
		}
	}

	var outBuf []byte
	// generate SCMPInfo response
	if s.decoded[len(s.decoded)-1] == slayers.LayerTypeSCMP &&
		(s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeTracerouteRequest ||
			s.scmpLayer.TypeCode.Type() == slayers.SCMPTypeEchoRequest) {
		err = s.replyToSCMPInfoRequest()
		if err != nil {
			log.Error("Reversing SCMP information", "err", err)
			return nil, netip.AddrPort{}, nil
		}
		payload := gopacket.Payload(s.scmpLayer.Payload)
		err = payload.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing payload", "err", err)
			return nil, netip.AddrPort{}, nil
		}
		s.outBuffer.PushLayer(payload.LayerType())

		err = s.scmpLayer.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing SCMP header", "err", err)
			return nil, netip.AddrPort{}, nil
		}
		s.outBuffer.PushLayer(s.scmpLayer.LayerType())

		if s.decoded[len(s.decoded)-2] == slayers.LayerTypeEndToEndExtn {
			err = s.e2e.SerializeTo(s.outBuffer, s.options)
			if err != nil {
				log.Error("Serializing e2e extension", "err", err)
				return nil, netip.AddrPort{}, nil
			}
			s.outBuffer.PushLayer(s.e2e.LayerType())
		}
		err = s.scionLayer.SerializeTo(s.outBuffer, s.options)
		if err != nil {
			log.Error("Serializing SCION header", "err", err)
			return nil, netip.AddrPort{}, nil
		}
		s.outBuffer.PushLayer(s.scionLayer.LayerType())
		outBuf = s.outBuffer.Bytes()
	} else { //forward incoming byte array
		outBuf = buf
	}

	return outBuf, dstAddrPort, nil
}

func (s *Server) replyToSCMPInfoRequest() error {
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
		return serrors.Wrap("parsing source address", err)
	}
	dst, err := s.scionLayer.DstAddr()
	if err != nil {
		return serrors.Wrap("parsing destination address", err)
	}
	if err := s.scionLayer.SetSrcAddr(dst); err != nil {
		return serrors.Wrap("setting source address", err)
	}
	if err := s.scionLayer.SetDstAddr(src); err != nil {
		return serrors.Wrap("setting destination address", err)
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
		return serrors.Wrap("reversing path", err)
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
		hostAddr := addr.Addr{IA: s.scionLayer.DstIA, Host: host}
		addrPort, ok := s.ServiceAddresses[hostAddr]
		if !ok {
			return netip.AddrPort{}, serrors.New("SVC destination not found",
				"Host", hostAddr)
		}
		return addrPort, nil
	case addr.HostTypeIP:
		return addrPortFromBytes(s.scionLayer.RawDstAddr, s.udpLayer.DstPort)
	default:
		return netip.AddrPort{}, serrors.New("invalid host type", "type", host.Type().String())
	}
}

type controlMessageParser interface {
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

// parseUnderlayAddr returns the underlay destination address on the outer UDP/IP wrapper.
// It returns an empty address, if the control message information is not present
// or it cannot be parsed.
// This is useful for checking that this address corresponds to the address of the inner
// UDP/SCION header. This refers to the safeguard for traffic reflection as discussed in:
// https://github.com/scionproto/scion/pull/4280#issuecomment-1775177351
func (s *Server) parseUnderlayAddr(oobuffer []byte) netip.Addr {
	if err := s.cmParser.Parse(oobuffer); err != nil {
		log.Error("Parsing Control Message Information", "err", err)
		return netip.Addr{}
	}
	if !s.cmParser.Destination().IsUnspecified() {
		pktAddr, ok := netip.AddrFromSlice(s.cmParser.Destination())
		if !ok {
			log.Error("Getting DST from IP_PKTINFO", "DST", s.cmParser.Destination())
			return netip.Addr{}
		}
		return pktAddr
	}
	log.Error("Destination in IP_PKTINFO is unspecified")
	return netip.Addr{}
}

func ListenAndServe(
	isDispatcher bool,
	svcAddrs map[addr.Addr]netip.AddrPort,
	addr *net.UDPAddr,
) error {

	conn, err := net.ListenUDP(addr.Network(), addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Debug(fmt.Sprintf("local address: %s", conn.LocalAddr()))
	dispServer := NewServer(isDispatcher, svcAddrs, conn)

	return dispServer.Serve()
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
		return netip.AddrPort{}, serrors.New("unexpected raw address byte slice format")
	}
	return netip.AddrPortFrom(a, port), nil
}

// setIPPktInfo sets the IP_PKTINFO.DST flag to the underlay socket. The IPv4 part
// covers the case for IPv4-only hosts. For hosts supporting dual stack, the IPv6
// part handles both 6 and 4 (with mapped addresses).
// The argument conn must not be nil. The returned conn will have the flag set,
// and the returned controlMessageParser can be used as a facilitator to
// parse the OOB after reading on the conn.
func setIPPktInfo(conn *net.UDPConn) (*net.UDPConn, controlMessageParser) {
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		panic(fmt.Sprintln("Connection address is not UDPAddr",
			"conn", conn.LocalAddr().Network()))
	}

	var cm controlMessageParser
	if udpAddr.AddrPort().Addr().Unmap().Is4() {
		err := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst, true)
		if err != nil {
			panic(fmt.Sprintf("cannot set IP_PKTINFO on socket: %s", err))
		}
		cm = ipv4ControlMessage{
			ControlMessage: new(ipv4.ControlMessage),
		}
	}
	if udpAddr.AddrPort().Addr().Unmap().Is6() {
		err := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst, true)
		if err != nil {
			panic(fmt.Sprintf("cannot set IP_PKTINFO on socket: %s", err))
		}
		cm = ipv6ControlMessage{
			ControlMessage: new(ipv6.ControlMessage),
		}
	}

	return conn, cm
}
