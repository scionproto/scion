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

package onehop

import (
	"hash"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	libpath "github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSenderCreatePath(t *testing.T) {
	s := &Sender{
		IA:  xtest.MustParseIA("1-ff00:0:110"),
		MAC: createMac(t),
	}
	now := time.Now()
	oneHopPath, err := s.CreatePath(12, now)
	require.NoError(t, err)

	var path onehop.Path
	err = path.DecodeFromBytes(oneHopPath.Raw)
	require.NoError(t, err)

	info := path.Info
	assert.True(t, info.ConsDir)
	assert.False(t, info.Peer)
	assert.Equal(t, util.TimeToSecs(now), info.Timestamp)

	hop := path.FirstHop
	assert.Equal(t, uint16(0), hop.ConsIngress)
	assert.Equal(t, uint16(12), hop.ConsEgress)
	assert.Equal(t, uint8(63), hop.ExpTime)
	mac := libpath.MAC(createMac(t), &info, &hop)
	assert.Equal(t, mac, hop.Mac[:6])
}

func TestSenderCreatePkt(t *testing.T) {
	s := &Sender{
		IA: xtest.MustParseIA("1-ff00:0:110"),
		Addr: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 4242,
		},
		MAC: createMac(t),
	}
	msg := testPacket()
	pkt, err := s.CreatePkt(msg)
	require.NoError(t, err)
	checkTestPkt(t, s, msg, pkt)
}

func TestSenderSend(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	conn := mock_snet.NewMockPacketConn(ctrl)
	s := &Sender{
		IA:   xtest.MustParseIA("1-ff00:0:110"),
		Conn: conn,
		Addr: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 4242,
		},
		MAC: createMac(t),
	}
	// Read from connection to unblock sender.
	ov := &net.UDPAddr{IP: net.IP{127, 0, 0, 42}, Port: 1337}
	var pkt *snet.Packet
	conn.EXPECT().WriteTo(gomock.Any(), ov).DoAndReturn(
		func(ipkt, _ interface{}) error {
			pkt = ipkt.(*snet.Packet)
			return nil
		},
	)
	msg := testPacket()
	err := s.Send(msg, ov)
	require.NoError(t, err)
	checkTestPkt(t, s, msg, pkt)

}

func testPacket() *Msg {
	return &Msg{
		Dst: snet.SCIONAddress{
			IA:   xtest.MustParseIA("1-ff00:0:111"),
			Host: addr.SvcCS,
		},
		Ifid:     12,
		InfoTime: time.Now(),
		Pld:      []byte{1, 2, 3, 4},
	}
}

func checkTestPkt(t *testing.T, s *Sender, msg *Msg, pkt *snet.Packet) {
	assert.Equal(t, msg.Dst, pkt.Destination)
	assert.Equal(t, snet.SCIONAddress{
		IA:   s.IA,
		Host: addr.HostFromIPStr("127.0.0.1"),
	}, pkt.Source)
	assert.True(t, pkt.Path.IsOHP())
	assert.Equal(t, uint16(4242), pkt.Payload.(snet.UDPPayload).SrcPort)
	assert.Equal(t, msg.Pld, pkt.Payload.(snet.UDPPayload).Payload)
}

func createMac(t *testing.T) hash.Hash {
	mac, err := scrypto.InitMac(make([]byte, 16))
	require.NoError(t, err)
	return mac
}
