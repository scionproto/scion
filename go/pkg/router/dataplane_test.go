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

package router_test

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/topology"
	underlayconn "github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/lib/underlay/conn/mock_conn"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/router"
	"github.com/scionproto/scion/go/pkg/router/mock_router"
)

func TestDataPlaneAddInternalInterface(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddInternalInterface(mock_conn.NewMockConn(ctrl), net.IP{}))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddInternalInterface(nil, nil))
	})
	t.Run("single set works", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddInternalInterface(mock_conn.NewMockConn(ctrl), net.IP{}))
	})
	t.Run("double set fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddInternalInterface(mock_conn.NewMockConn(ctrl), net.IP{}))
		assert.Error(t, d.AddInternalInterface(mock_conn.NewMockConn(ctrl), net.IP{}))
	})
}

func TestDataPlaneSetKey(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetKey([]byte("dummy")))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetKey(nil))
	})
	t.Run("single set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetKey([]byte("dummy key xxxxxx")))
	})
	t.Run("double set fails", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetKey([]byte("dummy key xxxxxx")))
		assert.Error(t, d.SetKey([]byte("dummy key xxxxxx")))
	})
}

func TestDataPlaneAddExternalInterface(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddExternalInterface(42, mock_conn.NewMockConn(ctrl)))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddExternalInterface(42, nil))
	})
	t.Run("normal add works", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddExternalInterface(42, mock_conn.NewMockConn(ctrl)))
		assert.NoError(t, d.AddExternalInterface(45, mock_conn.NewMockConn(ctrl)))
	})
	t.Run("overwrite fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddExternalInterface(42, mock_conn.NewMockConn(ctrl)))
		assert.Error(t, d.AddExternalInterface(42, mock_conn.NewMockConn(ctrl)))
	})
}

func TestDataPlaneAddSVC(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddSvc(addr.SvcCS, &net.IPAddr{}))
	})
	t.Run("adding nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddSvc(addr.SvcCS, nil))
	})
	t.Run("normal set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.IPAddr{}))
		assert.NoError(t, d.AddSvc(addr.SvcSIG, &net.IPAddr{}))
	})
	t.Run("set multiple times works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.IPAddr{}))
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.IPAddr{}))
	})
}

func TestDataPlaneAddNextHop(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddNextHop(45, &net.IPAddr{}))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddNextHop(45, nil))
	})
	t.Run("normal add works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddNextHop(45, &net.IPAddr{}))
		assert.NoError(t, d.AddNextHop(43, &net.IPAddr{}))
	})
	t.Run("overwrite fails", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddNextHop(45, &net.IPAddr{}))
		assert.Error(t, d.AddNextHop(45, &net.IPAddr{}))
	})
}

func TestDataPlaneRun(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := map[string]struct {
		prepareDP func(*gomock.Controller, chan<- struct{}) *router.DataPlane
	}{
		"route 10 msg from external to internal": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{}

				key := []byte("testkey_xxxxxxxx")
				local := xtest.MustParseIA("1-ff00:0:110")

				totalCount := 10
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				for i := 0; i < 10; i++ {
					ii := i
					mInternal.EXPECT().WriteBatch(gomock.Any()).DoAndReturn(
						func(ms underlayconn.Messages) (int, error) {
							want := bytes.Repeat([]byte("actualpayloadbytes"), ii)
							if len(ms[0].Buffers[0]) != len(want)+84 {
								return 1, nil
							}
							totalCount--
							if totalCount == 0 {
								done <- struct{}{}
							}
							return 1, nil
						})
				}
				_ = ret.AddInternalInterface(mInternal, net.IP{})

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages, meta []underlayconn.ReadMeta) (int, error) {
						// 10 scion messages to external
						for i := 0; i < totalCount; i++ {
							spkt, dpath := prepBaseMsg()
							spkt.DstIA = local
							dpath.HopFields = []*path.HopField{
								{ConsIngress: 41, ConsEgress: 40},
								{ConsIngress: 31, ConsEgress: 30},
								{ConsIngress: 1, ConsEgress: 0},
							}
							dpath.Base.PathMeta.CurrHF = 2
							dpath.HopFields[2].Mac = computeMAC(t, key,
								dpath.InfoFields[0], dpath.HopFields[2])
							spkt.Path = dpath
							payload := bytes.Repeat([]byte("actualpayloadbytes"), i)
							buffer := gopacket.NewSerializeBuffer()
							err := gopacket.SerializeLayers(buffer,
								gopacket.SerializeOptions{FixLengths: true},
								spkt, gopacket.Payload(payload))
							require.NoError(t, err)
							raw := buffer.Bytes()
							copy(m[i].Buffers[0], raw)
							m[i].N = len(raw)
						}
						return 10, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteBatch(gomock.Any()).Return(0, nil).AnyTimes()

				_ = ret.AddExternalInterface(1, mExternal)

				_ = ret.SetIA(local)
				_ = ret.SetKey(key)
				return ret
			},
		},
		"bfd bootstrap sessions": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{}
				postBFD := func(msg *ipv4.Message, id layers.BFDDiscriminator, a net.Addr) {
					scn := &slayers.SCION{
						NextHdr:  common.L4BFD,
						PathType: slayers.PathTypeEmpty,
						Path:     &scion.Decoded{},
					}
					bfdL := &layers.BFD{
						Version:           1,
						DetectMultiplier:  layers.BFDDetectMultiplier(2),
						MyDiscriminator:   id,
						YourDiscriminator: 0,
					}

					buffer := gopacket.NewSerializeBuffer()
					_ = gopacket.SerializeLayers(buffer,
						gopacket.SerializeOptions{FixLengths: true}, scn, bfdL)
					raw := buffer.Bytes()
					copy(msg.Buffers[0], raw)
					msg.Buffers[0] = msg.Buffers[0][:len(raw)]
					msg.N = len(raw)
					msg.Addr = a
				}
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages, meta []underlayconn.ReadMeta) (int, error) {
						postBFD(&m[0], 5, &net.IPAddr{IP: net.ParseIP("10.0.200.100").To4()})
						postBFD(&m[1], 34, &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()})
						return 2, nil
					},
				).Times(1)
				mInternal.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				mtx := sync.Mutex{}
				expectRemoteDiscriminators := map[int]struct{}{
					2:  {}, // local external interface
					5:  {}, // remote one interface
					34: {}, // remote two interfaces
				}
				mInternal.EXPECT().WriteBatch(gomock.Any()).DoAndReturn(
					func(ms underlayconn.Messages) (int, error) {
						pkt := gopacket.NewPacket(ms[0].Buffers[0],
							slayers.LayerTypeSCION, gopacket.Default)
						if b := pkt.Layer(layers.LayerTypeBFD); b != nil {
							v := int(b.(*layers.BFD).YourDiscriminator)
							mtx.Lock()
							defer mtx.Unlock()
							delete(expectRemoteDiscriminators, v)
							if len(expectRemoteDiscriminators) == 0 {
								done <- struct{}{}
							}
							return 1, nil
						}
						return 0, fmt.Errorf("no valid BFD message")
					}).MinTimes(1)
				mInternal.EXPECT().WriteBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages, meta []underlayconn.ReadMeta) (int, error) {
						postBFD(&m[0], 2, nil)
						return 1, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteBatch(gomock.Any()).DoAndReturn(
					func(ms underlayconn.Messages) (int, error) {
						pkt := gopacket.NewPacket(ms[0].Buffers[0],
							slayers.LayerTypeSCION, gopacket.Default)
						if b := pkt.Layer(layers.LayerTypeBFD); b != nil {
							v := int(b.(*layers.BFD).YourDiscriminator)
							mtx.Lock()
							defer mtx.Unlock()
							delete(expectRemoteDiscriminators, v)
							if len(expectRemoteDiscriminators) == 0 {
								done <- struct{}{}
							}
							return 1, nil
						}
						return 0, fmt.Errorf("no valid BFD message")
					}).MinTimes(1)
				mExternal.EXPECT().WriteBatch(gomock.Any()).Return(0, nil).AnyTimes()

				_ = ret.AddInternalInterface(mInternal, net.IP{})
				_ = ret.AddNextHop(3, &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()})
				_ = ret.AddNextHopBFD(3, &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()})
				_ = ret.AddNextHop(4, &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()})
				_ = ret.AddNextHopBFD(4, &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()})
				_ = ret.AddNextHop(5, &net.IPAddr{IP: net.ParseIP("10.0.200.100").To4()})
				_ = ret.AddNextHopBFD(5, &net.IPAddr{IP: net.ParseIP("10.0.200.100").To4()})
				_ = ret.AddExternalInterface(1, mExternal)
				_ = ret.AddExternalInterfaceBFD(1, mExternal)

				return ret
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ch := make(chan struct{})
			dp := tc.prepareDP(ctrl, ch)
			errors := make(chan error)
			go func() {
				errors <- dp.Run()
			}()

			for done := false; !done; {
				select {
				case <-ch:
					done = true
				case err := <-errors:
					require.NoError(t, err)
				case <-time.After(3 * time.Second):
					t.Fatalf("time out")
				}
			}
		})
	}
}

func TestProcessPkt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")

	testCases := map[string]struct {
		mockMsg      func(bool) *ipv4.Message
		prepareDP    func(*gomock.Controller) *router.DataPlane
		srcInterface uint16
		assertFunc   assert.ErrorAssertionFunc
	}{
		"inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dst := &net.IPAddr{IP: net.ParseIP("10.0.100.100").To4()}
				_ = spkt.SetDstAddr(dst)
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 01, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: dst.IP, Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(map[uint16]router.BatchConn{
					uint16(1): mock_router.NewMockBatchConn(ctrl),
				}, nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 0, ConsEgress: 1},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 41, ConsEgress: 40},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.HopFields[0].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[0])
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath()
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 0,
			assertFunc:   assert.NoError,
		},
		"brtransit": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(map[uint16]router.BatchConn{
					uint16(2): mock_router.NewMockBatchConn(ctrl),
				}, nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 2},
					{ConsIngress: 40, ConsEgress: 41},
				}
				dpath.Base.PathMeta.CurrHF = 1
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath()
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"brtransit non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(map[uint16]router.BatchConn{
					uint16(2): mock_router.NewMockBatchConn(ctrl),
				}, nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 2, ConsEgress: 1},
					{ConsIngress: 40, ConsEgress: 41},
				}
				dpath.Base.PathMeta.CurrHF = 1
				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath())
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"astransit direct": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, mock_router.NewMockBatchConn(ctrl),
					map[uint16]net.Addr{
						uint16(3): &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 3},
					{ConsIngress: 50, ConsEgress: 51},
				}
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"astransit xover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, mock_router.NewMockBatchConn(ctrl),
					map[uint16]net.Addr{
						uint16(3): &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg()
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF: 2,
							SegLen: [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					InfoFields: []*path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(time.Now())},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(time.Now())},
					},
					HopFields: []*path.HopField{
						{ConsIngress: 0, ConsEgress: 1},  // IA 110
						{ConsIngress: 31, ConsEgress: 0}, // Src
						{ConsIngress: 0, ConsEgress: 51}, // Dst
						{ConsIngress: 3, ConsEgress: 0},  // IA 110
					},
				}
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				dpath.HopFields[3].Mac = computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[3])

				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath())
				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 51,
			assertFunc:   assert.NoError,
		},
		"svc": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]net.Addr{
						addr.HostSVCFromString("CS"): {
							&net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()},
						},
					},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				_ = spkt.SetDstAddr(addr.HostSVCFromString("CS"))
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(),
						Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"svc nobackend": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]net.Addr{},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				_ = spkt.SetDstAddr(addr.HostSVCFromString("CS"))
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
		},
		"svc invalid": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]net.Addr{},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				_ = spkt.SetDstAddr(addr.HostSVCFromString("BS"))
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
		},
		"onehop inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(map[uint16]router.BatchConn{
					uint16(2): mock_router.NewMockBatchConn(ctrl),
				}, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]net.Addr{
						addr.SvcCS: {&net.IPAddr{IP: net.ParseIP("172.0.2.10")}},
					},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg()
				spkt.PathType = slayers.PathTypeOneHop
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				err := spkt.SetDstAddr(addr.SVCMcast | addr.SvcCS)
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: 0x100,
					},
					FirstHop: path.HopField{
						IngressRouterAlert: true,
						EgressRouterAlert:  true,
						ExpTime:            63,
						ConsIngress:        0,
						ConsEgress:         21,
						Mac:                []byte{1, 2, 3, 4, 5, 6},
					},
				}
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.SecondHop = path.HopField{
					ExpTime:     63,
					ConsIngress: 1,
				}
				dpath.SecondHop.Mac = computeMAC(t, key, &dpath.Info, &dpath.SecondHop)

				sp, err := dpath.ToSCIONDecoded()
				require.NoError(t, err)
				err = sp.Reverse()
				require.NoError(t, err)

				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.UDPAddr{
					IP:   net.ParseIP("172.0.2.10"),
					Port: topology.EndhostPort,
				}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"reversed onehop outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(map[uint16]router.BatchConn{
					uint16(1): mock_router.NewMockBatchConn(ctrl),
				}, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]net.Addr{
						addr.SvcCS: {&net.IPAddr{IP: net.ParseIP("172.0.2.10")}},
					},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg()
				spkt.PathType = slayers.PathTypeSCION
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				err := spkt.SetDstAddr(addr.SVCMcast | addr.SvcCS)
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: util.TimeToSecs(time.Now()),
					},
					FirstHop: path.HopField{
						IngressRouterAlert: true,
						EgressRouterAlert:  true,
						ExpTime:            63,
						ConsIngress:        0,
						ConsEgress:         21,
						Mac:                []byte{1, 2, 3, 4, 5, 6},
					},
					SecondHop: path.HopField{
						IngressRouterAlert: true,
						EgressRouterAlert:  true,
						ExpTime:            63,
						ConsIngress:        1,
					},
				}
				dpath.SecondHop.Mac = computeMAC(t, key, &dpath.Info, &dpath.SecondHop)
				sp, err := dpath.ToSCIONDecoded()
				require.NoError(t, err)
				require.NoError(t, sp.IncPath())
				err = sp.Reverse()
				require.NoError(t, err)

				if !afterProcessing {
					return toMsg(t, spkt, sp)
				}

				require.NoError(t, sp.IncPath())
				ret := toMsg(t, spkt, sp)
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 0,
			assertFunc:   assert.NoError,
		},
		"onehop outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(map[uint16]router.BatchConn{
					uint16(2): mock_router.NewMockBatchConn(ctrl),
				}, mock_router.NewMockBatchConn(ctrl), nil,
					nil,
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg()
				spkt.PathType = slayers.PathTypeOneHop
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				err := spkt.SetDstAddr(addr.SVCMcast | addr.SvcCS)
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: 0x100,
					},
					FirstHop: path.HopField{
						IngressRouterAlert: true,
						EgressRouterAlert:  true,
						ExpTime:            63,
						ConsIngress:        0,
						ConsEgress:         2,
					},
				}
				dpath.FirstHop.Mac = computeMAC(t, key, &dpath.Info, &dpath.FirstHop)

				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.Info.UpdateSegID(dpath.FirstHop.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 0,
			assertFunc:   assert.NoError,
		},
		"invalid dest": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]net.Addr{},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg()
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:f1")
				dpath.HopFields = []*path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 404},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 1
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP(ctrl)
			input, want := tc.mockMsg(false), tc.mockMsg(true)
			buffer := gopacket.NewSerializeBuffer()
			origMsg := make([]byte, len(input.Buffers[0]))
			copy(origMsg, input.Buffers[0])
			c, err := dp.ProcessPkt(tc.srcInterface, input, slayers.SCION{}, origMsg, buffer)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			assert.NotNil(t, c)
			// input is modified by processPkt
			assert.Equal(t, want, input)
		})
	}
}

func toMsg(t *testing.T, spkt *slayers.SCION, dpath slayers.Path) *ipv4.Message {
	t.Helper()
	ret := &ipv4.Message{}
	spkt.Path = dpath
	buffer := gopacket.NewSerializeBuffer()
	payload := []byte("actualpayloadbytes")
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		spkt, gopacket.Payload(payload))
	require.NoError(t, err)
	raw := buffer.Bytes()
	ret.Buffers = make([][]byte, 1)
	ret.Buffers[0] = make([]byte, 1500)
	copy(ret.Buffers[0], raw)
	ret.N = len(raw)
	ret.Buffers[0] = ret.Buffers[0][:ret.N]
	return ret
}

func prepBaseMsg() (*slayers.SCION, *scion.Decoded) {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      common.L4UDP,
		PathType:     slayers.PathTypeSCION,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []*path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(time.Now())},
		},

		HopFields: []*path.HopField{},
	}
	return spkt, dpath
}

func computeMAC(t *testing.T, key []byte, info *path.InfoField, hf *path.HopField) []byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf)

}
