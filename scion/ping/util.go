// Copyright 2020 Anapaya Systems
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

package ping

import (
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// Size computes the full SCION packet size for an address pair with a given
// payload size.
func Size(local, remote addr.Addr, dPath snet.DataplanePath, pldSize int) (int, error) {
	pkt, err := pack(local, remote, dPath, snet.SCMPEchoRequest{Payload: make([]byte, pldSize)})
	if err != nil {
		return 0, err
	}
	if err := pkt.Serialize(); err != nil {
		return 0, err
	}
	return len(pkt.Bytes), nil
}

func pack(
	local, remote addr.Addr,
	dPath snet.DataplanePath,
	req snet.SCMPEchoRequest,
) (*snet.Packet, error) {
	_, isEmpty := dPath.(path.Empty)
	if isEmpty && !local.IA.Equal(remote.IA) {
		return nil, serrors.New("no path for remote ISD-AS", "local", local.IA, "remote", remote.IA)
	}
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: remote,
			Source:      local,
			Path:        dPath,
			Payload:     req,
		},
	}
	return pkt, nil
}
