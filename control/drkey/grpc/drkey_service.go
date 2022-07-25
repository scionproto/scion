// Copyright 2022 ETH Zurich
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

package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
	"inet.af/netaddr"

	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	drkeypb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

type Engine interface {
	// Storing SVs in the server allows for the server to still have access to
	// handed out secrets even after rebooting. It is not critical to the server
	// to derive secret values fast, so the lookup operation is acceptable.
	GetSecretValue(ctx context.Context, meta drkey.SecretValueMeta) (drkey.SecretValue, error)
	GetLevel1Key(ctx context.Context, meta drkey.Level1Meta) (drkey.Level1Key, error)

	DeriveLevel1(meta drkey.Level1Meta) (drkey.Level1Key, error)
	DeriveASHost(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	DeriveHostAS(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error)
	DeriveHostHost(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
}

// Server keeps track of the drkeys.
type Server struct {
	LocalIA addr.IA
	Engine  Engine
	// AllowedSVHostProto is a set of (Host,Protocol) pairs that represents the allowed
	// protocols hosts can obtain secrets values.
	AllowedSVHostProto map[config.HostProto]struct{}
}

// DRKeyLevel1 handles a level 1 request and returns a response.
func (d *Server) DRKeyLevel1(
	ctx context.Context,
	req *cppb.DRKeyLevel1Request,
) (*cppb.DRKeyLevel1Response, error) {

	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("cannot retrieve peer information from ctx")
	}
	dstIA, err := extractIAFromPeer(peer)
	if err != nil {
		return nil, serrors.WrapStr("retrieving info from certificate", err)
	}

	lvl1Meta, err := getMeta(req.ProtocolId, req.ValTime, d.LocalIA, dstIA)
	if err != nil {
		return nil, serrors.WrapStr("invalid DRKey Level1 request", err)
	}

	// validate requested ProtoID is specific
	if !lvl1Meta.ProtoId.IsPredefined() {
		return nil, serrors.New("the requested protocol id is not recognized",
			"proto_id", lvl1Meta.ProtoId)
	}

	lvl1Key, err := d.Engine.DeriveLevel1(lvl1Meta)
	if err != nil {
		return nil, serrors.WrapStr("deriving level 1 key", err)
	}
	resp := keyToLevel1Resp(lvl1Key)
	return resp, nil
}

// DRKeyIntraLevel1 handles a level 1 request from a local host and returns a response.
func (d *Server) DRKeyIntraLevel1(
	ctx context.Context,
	req *cppb.DRKeyIntraLevel1Request,
) (*cppb.DRKeyIntraLevel1Response, error) {

	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("cannot retrieve peer information from ctx")
	}

	if d.LocalIA != addr.IA(req.SrcIa) && d.LocalIA != addr.IA(req.DstIa) {
		return nil, serrors.New("local IA is not part of the request")
	}

	meta, err := getMeta(req.ProtocolId, req.ValTime, addr.IA(req.SrcIa), addr.IA(req.DstIa))
	if err != nil {
		return nil, serrors.WrapStr("parsing AS-AS request", err)
	}
	if err := d.validateAllowedHost(meta.ProtoId, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating AS-AS request", err)
	}

	lvl1Key, err := d.Engine.GetLevel1Key(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting AS-AS host key", err)
	}

	resp := keyToASASResp(lvl1Key)
	return resp, nil
}

// DRKeyASHost handles a AS-Host request from a local host and returns a response.
func (d *Server) DRKeyASHost(
	ctx context.Context,
	req *cppb.DRKeyASHostRequest,
) (*cppb.DRKeyASHostResponse, error) {

	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("cannot retrieve peer information from ctx")
	}

	meta, err := requestToASHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing DRKey AS-Host request", err)
	}
	if err := validateASHostReq(meta, d.LocalIA, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating AS-Host request", err)
	}

	asHostKey, err := d.Engine.DeriveASHost(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("deriving AS-Host request", err)
	}

	resp := keyToASHostResp(asHostKey)
	return resp, nil
}

// DRKeyHostAS handles a Host-AS request from a local host and returns a response.
func (d *Server) DRKeyHostAS(
	ctx context.Context,
	req *cppb.DRKeyHostASRequest,
) (*cppb.DRKeyHostASResponse, error) {

	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("cannot retrieve peer information from ctx")
	}

	meta, err := requestToHostASMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-AS request", err)
	}
	if err := validateHostASReq(meta, d.LocalIA, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating Host-AS request", err)
	}
	key, err := d.Engine.DeriveHostAS(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("deriving Host-AS request", err)
	}

	resp := keyToHostASResp(key)
	return resp, nil
}

// DRKeyHostHost handles a Host-Host request from a local host and returns a response.
func (d *Server) DRKeyHostHost(
	ctx context.Context,
	req *cppb.DRKeyHostHostRequest,
) (*cppb.DRKeyHostHostResponse, error) {

	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("cannot retrieve peer information from ctx")
	}

	meta, err := requestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-Host request", err)
	}
	if err := validateHostHostReq(meta, d.LocalIA, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating Host-Host request", err)
	}

	key, err := d.Engine.DeriveHostHost(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("deriving Host-Host request", err)
	}

	resp := keyToHostHostResp(key)
	return resp, nil
}

// DRKeySecretValue handles a SecretValue request and returns a response.
func (d *Server) DRKeySecretValue(
	ctx context.Context,
	req *cppb.DRKeySecretValueRequest,
) (*cppb.DRKeySecretValueResponse, error) {

	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("cannot retrieve peer information from ctx")
	}

	meta, err := secretRequestToMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing Host-Host request", err)
	}
	if err := d.validateAllowedHost(meta.ProtoId, peer.Addr); err != nil {
		return nil, serrors.WrapStr("validating SV request", err)
	}
	sv, err := d.Engine.GetSecretValue(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting SV from persistence", err)
	}
	resp := secretToProtoResp(sv)
	return resp, nil
}

// validateAllowedHost checks that the requester is authorized to receive a SV.
func (d *Server) validateAllowedHost(protoId drkey.Protocol, peerAddr net.Addr) error {
	tcpAddr, ok := peerAddr.(*net.TCPAddr)
	if !ok {
		return serrors.New("invalid peer address type, expected *net.TCPAddr",
			"peer", peerAddr, "type", common.TypeOf(peerAddr))
	}
	localAddr, ok := netaddr.FromStdIP(tcpAddr.IP)
	if !ok {
		return serrors.New("unable to parse IP", "addr", tcpAddr.IP.String())
	}
	hostProto := config.HostProto{
		Host:  localAddr,
		Proto: protoId,
	}

	_, foundSet := d.AllowedSVHostProto[hostProto]
	if foundSet {
		log.Debug("Authorized delegated secret",
			"protocol", protoId.String(),
			"requester_address", localAddr.String(),
		)
		return nil
	}
	return serrors.New("endhost not allowed for DRKey request",
		"protocol", protoId.String(),
		"requester_address", localAddr.String(),
	)
}

// validateASHostReq returns and error if the requesting host is different from the
// requested dst host. The source AS infraestructure nodes are not supposed to contact
// the local CS but to derive this key from the SV instead.
func validateASHostReq(meta drkey.ASHostMeta, localIA addr.IA, peerAddr net.Addr) error {
	hostAddr, err := hostAddrFromPeer(peerAddr)
	if err != nil {
		return err
	}

	if !meta.DstIA.Equal(localIA) {
		return serrors.New("invalid request, req.dstIA != localIA",
			"request_dst_isd_as", meta.DstIA, "local_isd_as", localIA)
	}
	dstHost := addr.HostFromIPStr(meta.DstHost)
	if !hostAddr.Equal(dstHost) {
		return serrors.New("invalid request, dst_host != remote host",
			"dst_host", dstHost, "remote_host", hostAddr)
	}
	return nil
}

// validateASHostReq returns and error if the requesting host is different from the
// requested src host. The dst AS infraestructure nodes are not supposed to contact
// the local CS but to derive this key from the SV instead.
func validateHostASReq(meta drkey.HostASMeta, localIA addr.IA, peerAddr net.Addr) error {
	hostAddr, err := hostAddrFromPeer(peerAddr)
	if err != nil {
		return err
	}

	if !meta.SrcIA.Equal(localIA) {
		return serrors.New("invalid request, req.SrcIA != localIA",
			"request_src_isd_as", meta.SrcIA, "local_isd_as", localIA)
	}
	srcHost := addr.HostFromIPStr(meta.SrcHost)
	if !hostAddr.Equal(srcHost) {
		return serrors.New("invalid request, src_host != remote host",
			"src_host", srcHost, "remote_host", hostAddr)
	}
	return nil
}

// validateHostHostReq returns and error if the requesting host is different from the
// requested src host or the dst host.
func validateHostHostReq(meta drkey.HostHostMeta, localIA addr.IA, peerAddr net.Addr) error {
	hostAddr, err := hostAddrFromPeer(peerAddr)
	if err != nil {
		return err
	}
	srcHost := addr.HostFromIPStr(meta.SrcHost)
	dstHost := addr.HostFromIPStr(meta.DstHost)

	if !((meta.SrcIA.Equal(localIA) && hostAddr.Equal(srcHost)) ||
		(meta.DstIA.Equal(localIA) && hostAddr.Equal(dstHost))) {
		return serrors.New(
			"invalid request",
			"local_isd_as", localIA,
			"src_isd_as", meta.SrcIA,
			"dst_isd_as", meta.DstIA,
			"src_host", srcHost,
			"dst_host", dstHost,
			"remote_host", hostAddr,
		)
	}
	return nil
}

func hostAddrFromPeer(peerAddr net.Addr) (addr.HostAddr, error) {
	tcpAddr, ok := peerAddr.(*net.TCPAddr)
	if !ok {
		return nil, serrors.New("invalid peer address type, expected *net.TCPAddr",
			"peer", peerAddr, "type", common.TypeOf(peerAddr))
	}
	return addr.HostFromIP(tcpAddr.IP), nil
}

func getMeta(protoId drkeypb.Protocol, ts *timestamppb.Timestamp, srcIA,
	dstIA addr.IA) (drkey.Level1Meta, error) {
	err := ts.CheckValid()
	if err != nil {
		return drkey.Level1Meta{}, serrors.WrapStr("invalid valTime from pb req", err)
	}
	return drkey.Level1Meta{
		Validity: ts.AsTime(),
		ProtoId:  drkey.Protocol(protoId),
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}, nil
}

func extractIAFromPeer(peer *peer.Peer) (addr.IA, error) {
	if peer.AuthInfo == nil {
		return 0, serrors.New("no auth info", "peer", peer)
	}
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return 0, serrors.New("auth info is not of type TLS info",
			"peer", peer, "auth_type", peer.AuthInfo.AuthType())
	}
	chain := tlsInfo.State.PeerCertificates
	certIA, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return 0, serrors.WrapStr("extracting IA from peer cert", err)
	}
	return certIA, nil
}
