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
	"hash"
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
	libepic "github.com/scionproto/scion/go/lib/epic"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/topology"
	underlayconn "github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/lib/underlay/conn/mock_conn"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/router"
	"github.com/scionproto/scion/go/pkg/router/control"
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
	t.Run("succeeds after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
	})
	t.Run("adding nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddSvc(addr.SvcCS, nil))
	})
	t.Run("normal set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
		assert.NoError(t, d.AddSvc(addr.SvcSIG, &net.UDPAddr{}))
	})
	t.Run("set multiple times works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
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

	metrics := router.NewMetrics()

	testCases := map[string]struct {
		prepareDP func(*gomock.Controller, chan<- struct{}) *router.DataPlane
	}{
		"route 10 msg from external to internal": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}

				key := []byte("testkey_xxxxxxxx")
				local := xtest.MustParseIA("1-ff00:0:110")

				totalCount := 10
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

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
				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						// 10 scion messages to external
						for i := 0; i < totalCount; i++ {
							spkt, dpath := prepBaseMsg(time.Now())
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
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteBatch(gomock.Any()).Return(0, nil).AnyTimes()

				_ = ret.AddExternalInterface(1, mExternal)

				_ = ret.SetIA(local)
				_ = ret.SetKey(key)
				return ret
			},
		},
		"bfd bootstrap internal session": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}

				postInternalBFD := func(id layers.BFDDiscriminator, src *net.UDPAddr) []byte {
					scn := &slayers.SCION{
						NextHdr:  common.L4BFD,
						PathType: empty.PathType,
						Path:     &empty.Path{},
					}
					bfdL := &layers.BFD{
						Version:           1,
						DetectMultiplier:  layers.BFDDetectMultiplier(2),
						MyDiscriminator:   layers.BFDDiscriminator(id),
						YourDiscriminator: 0,
					}

					_ = scn.SetSrcAddr(&net.IPAddr{IP: src.IP})
					buffer := gopacket.NewSerializeBuffer()
					_ = gopacket.SerializeLayers(buffer,
						gopacket.SerializeOptions{FixLengths: true}, scn, bfdL)
					return buffer.Bytes()
				}

				mtx := sync.Mutex{}
				expectRemoteDiscriminators := map[layers.BFDDiscriminator]struct{}{}
				routers := map[net.Addr][]uint16{
					&net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4()}: {2, 3},
					&net.UDPAddr{IP: net.ParseIP("10.0.200.201").To4()}: {4},
				}

				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						i := 0
						for k := range routers { // post a BFD from each neighbor router
							disc := layers.BFDDiscriminator(i)
							raw := postInternalBFD(disc, k.(*net.UDPAddr))
							copy(m[i].Buffers[0], raw)
							m[i].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
							m[i].Buffers[0] = m[i].Buffers[0][:len(raw)]
							m[i].N = len(raw)
							expectRemoteDiscriminators[disc] = struct{}{}
							i++
						}
						return len(routers), nil
					},
				).Times(1)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mInternal.EXPECT().WriteBatch(gomock.Any()).DoAndReturn(
					func(ms underlayconn.Messages) (int, error) {
						pkt := gopacket.NewPacket(ms[0].Buffers[0],
							slayers.LayerTypeSCION, gopacket.Default)
						if b := pkt.Layer(layers.LayerTypeBFD); b != nil {
							v := b.(*layers.BFD).YourDiscriminator
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

				local := &net.UDPAddr{IP: net.ParseIP("10.0.200.100").To4()}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				for remote, ifIDs := range routers {
					for _, ifID := range ifIDs {
						_ = ret.AddNextHop(ifID, remote)
						_ = ret.AddNextHopBFD(ifID, local, remote.(*net.UDPAddr), bfd(), "")
					}
				}
				return ret
			},
		},
		"bfd sender internal": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				localAddr := &net.UDPAddr{IP: net.ParseIP("10.0.200.100").To4()}
				remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4()}
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().WriteBatch(gomock.Any()).DoAndReturn(
					func(ms underlayconn.Messages) (int, error) {
						pkt := gopacket.NewPacket(ms[0].Buffers[0],
							slayers.LayerTypeSCION, gopacket.Default)

						if b := pkt.Layer(layers.LayerTypeBFD); b == nil {
							return 1, nil
						}

						if scnL := pkt.Layer(slayers.LayerTypeSCION); scnL != nil {
							s := scnL.(*slayers.SCION)
							a, err := s.SrcAddr()
							if err != nil {
								return 1, nil
							}
							if !bytes.Equal(a.(*net.IPAddr).IP, localAddr.IP) {
								return 1, nil
							}

							b, err := s.DstAddr()
							if err != nil {
								return 1, nil
							}
							if !bytes.Equal(b.(*net.IPAddr).IP, remoteAddr.IP) {
								return 1, nil
							}

							if s.PathType != empty.PathType {
								return 1, nil
							}
							if _, ok := s.Path.(empty.Path); !ok {
								return 1, nil
							}
						}
						done <- struct{}{}
						return 1, nil
					}).MinTimes(1)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				_ = ret.AddNextHop(3, localAddr)
				_ = ret.AddNextHopBFD(3, localAddr, remoteAddr, bfd(), "")

				return ret
			},
		},
		"bfd sender external": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				ifID := uint16(1)
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteBatch(gomock.Any()).DoAndReturn(
					func(ms underlayconn.Messages) (int, error) {
						pkt := gopacket.NewPacket(ms[0].Buffers[0],
							slayers.LayerTypeSCION, gopacket.Default)

						if b := pkt.Layer(layers.LayerTypeBFD); b == nil {
							return 1, nil
						}

						if scnL := pkt.Layer(slayers.LayerTypeSCION); scnL != nil {
							s := scnL.(*slayers.SCION)
							if s.PathType != onehop.PathType {
								return 1, nil
							}

							v, ok := s.Path.(*onehop.Path)
							if !ok {
								return 1, nil
							}
							if v.FirstHop.ConsEgress != ifID {
								return 1, nil
							}
						}

						done <- struct{}{}
						return 1, nil
					}).MinTimes(1)
				mExternal.EXPECT().WriteBatch(gomock.Any()).Return(0, nil).AnyTimes()

				local := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:1"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.100")},
				}
				remote := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:3"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.200")},
				}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				_ = ret.AddExternalInterface(ifID, mExternal)
				_ = ret.AddExternalInterfaceBFD(ifID, mExternal, local, remote, bfd())

				return ret
			},
		},
		"bfd bootstrap external session": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}

				postExternalBFD := func(id layers.BFDDiscriminator, fromIfID uint16) []byte {
					scn := &slayers.SCION{
						NextHdr:  common.L4BFD,
						PathType: onehop.PathType,
						Path: &onehop.Path{
							FirstHop: path.HopField{ConsEgress: fromIfID},
						},
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
					return buffer.Bytes()
				}

				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mtx := sync.Mutex{}
				expectRemoteDiscriminators := map[int]struct{}{}

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						raw := postExternalBFD(2, 1)
						expectRemoteDiscriminators[2] = struct{}{}
						copy(m[0].Buffers[0], raw)
						m[0].Buffers[0] = m[0].Buffers[0][:len(raw)]
						m[0].N = len(raw)
						return 1, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

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

				local := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:1"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.100")},
				}
				remote := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:3"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.200")},
				}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				_ = ret.AddExternalInterface(1, mExternal)
				_ = ret.AddExternalInterfaceBFD(1, mExternal, local, remote, bfd())

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
	now := time.Now()
	epicTS, err := libepic.CreateTimestamp(now, now)
	require.NoError(t, err)

	testCases := map[string]struct {
		mockMsg      func(bool) *ipv4.Message
		prepareDP    func(*gomock.Controller) *router.DataPlane
		srcInterface uint16
		assertFunc   assert.ErrorAssertionFunc
	}{
		"inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						2: topology.Parent,
						1: topology.Child,
					}, nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						1: topology.Core,
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]net.Addr{
						uint16(3): &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]net.Addr{
						uint16(3): &net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
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
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
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
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]*net.UDPAddr{
						addr.HostSVCFromString("CS"): {
							&net.UDPAddr{
								IP:   net.ParseIP("10.0.200.200").To4(),
								Port: topology.EndhostPort,
							},
						},
					},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]*net.UDPAddr{},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]*net.UDPAddr{},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					nil,
					mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]*net.UDPAddr{
						addr.SvcCS: {&net.UDPAddr{
							IP:   net.ParseIP("172.0.2.10"),
							Port: topology.EndhostPort,
						}},
					},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
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
				_, err = sp.Reverse()
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
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					nil,
					mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]*net.UDPAddr{
						addr.SvcCS: {&net.UDPAddr{
							IP:   net.ParseIP("172.0.2.10"),
							Port: topology.EndhostPort,
						}},
					},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = scion.PathType
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
				p, err := sp.Reverse()
				require.NoError(t, err)
				sp = p.(*scion.Decoded)

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
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					nil,
					mock_router.NewMockBatchConn(ctrl), nil,
					nil,
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
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
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.HostSVC][]*net.UDPAddr{},
					xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
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
		"epic inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)

				prepareEpicCrypto(t, spkt, epicpath, dpath, key)
				return toIP(t, spkt, epicpath, afterProcessing)
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"epic malformed path": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)
				prepareEpicCrypto(t, spkt, epicpath, dpath, key)

				// Wrong path type
				return toIP(t, spkt, &scion.Decoded{}, afterProcessing)
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
		},
		"epic invalid timestamp": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)

				// Invalid timestamp
				epicpath.PktID.Timestamp = epicpath.PktID.Timestamp + 250000

				prepareEpicCrypto(t, spkt, epicpath, dpath, key)
				return toIP(t, spkt, epicpath, afterProcessing)
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
		},
		"epic invalid LHVF": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)
				prepareEpicCrypto(t, spkt, epicpath, dpath, key)

				// Invalid LHVF
				epicpath.LHVF = []byte{0, 0, 0, 0}

				return toIP(t, spkt, epicpath, afterProcessing)
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
			result, err := dp.ProcessPkt(tc.srcInterface, input, slayers.SCION{}, origMsg,
				buffer)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			assert.NotNil(t, result.OutConn)
			outPkt := &ipv4.Message{
				Buffers: [][]byte{result.OutPkt},
				Addr:    result.OutAddr,
			}
			assert.Equal(t, want, outPkt)
		})
	}
}

func toMsg(t *testing.T, spkt *slayers.SCION, dpath path.Path) *ipv4.Message {
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

func prepBaseMsg(now time.Time) (*slayers.SCION, *scion.Decoded) {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      common.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
		PayloadLen:   18,
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
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []*path.HopField{},
	}
	return spkt, dpath
}

func prepEpicMsg(t *testing.T, afterProcessing bool, key []byte,
	epicTS uint32, now time.Time) (*slayers.SCION, *epic.Path, *scion.Decoded) {

	spkt, dpath := prepBaseMsg(now)
	spkt.PathType = epic.PathType

	spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
	dpath.HopFields = []*path.HopField{
		{ConsIngress: 41, ConsEgress: 40},
		{ConsIngress: 31, ConsEgress: 30},
		{ConsIngress: 01, ConsEgress: 0},
	}
	dpath.Base.PathMeta.CurrHF = 2
	dpath.Base.PathMeta.CurrINF = 0

	pktID := epic.PktID{
		Timestamp: epicTS,
		Counter:   libepic.PktCounterFromCore(1, 2),
	}

	epicpath := &epic.Path{
		PktID: pktID,
		PHVF:  make([]byte, 4),
		LHVF:  make([]byte, 4),
	}
	spkt.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("10.0.200.200").To4()})
	spkt.Path = epicpath

	return spkt, epicpath, dpath
}

func prepareEpicCrypto(t *testing.T, spkt *slayers.SCION,
	epicpath *epic.Path, dpath *scion.Decoded, key []byte) {

	// Calculate SCION MAC
	dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
	scionPath, err := dpath.ToRaw()
	require.NoError(t, err)
	epicpath.ScionPath = scionPath

	// Generate EPIC authenticator
	authLast := computeFullMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])

	// Calculate PHVF and LHVF
	macLast, err := libepic.CalcMac(authLast, epicpath.PktID,
		spkt, dpath.InfoFields[0].Timestamp)
	require.NoError(t, err)
	copy(epicpath.LHVF, macLast)
}

func toIP(t *testing.T, spkt *slayers.SCION, path path.Path, afterProcessing bool) *ipv4.Message {
	// Encapsulate in IPv4
	dst := &net.IPAddr{IP: net.ParseIP("10.0.100.100").To4()}
	require.NoError(t, spkt.SetDstAddr(dst))
	ret := toMsg(t, spkt, path)
	if afterProcessing {
		ret.Addr = &net.UDPAddr{IP: dst.IP, Port: topology.EndhostPort}
		ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
	}
	return ret
}

func computeMAC(t *testing.T, key []byte, info *path.InfoField, hf *path.HopField) []byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf)
}

func computeFullMAC(t *testing.T, key []byte, info *path.InfoField, hf *path.HopField) []byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.FullMAC(mac, info, hf)
}

func createMac(t *testing.T) hash.Hash {
	mac, err := scrypto.InitMac(make([]byte, 16))
	xtest.FailOnErr(t, err)
	return mac
}

func bfd() control.BFD {
	return control.BFD{
		DetectMult:            3,
		DesiredMinTxInterval:  1 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
	}
}
