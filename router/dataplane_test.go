// Copyright 2020 Anapaya Systems
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

package router_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	libepic "github.com/scionproto/scion/pkg/experimental/epic"
	"github.com/scionproto/scion/pkg/private/ptr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/topology"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/control"
	"github.com/scionproto/scion/router/mock_router"
)

var (
	metrics    = router.GetMetrics()
	srcUDPPort = 50001
	dstUDPPort = 50002
)

func TestDataPlaneAddInternalInterface(t *testing.T) {
	internalIP := netip.MustParseAddr("198.51.100.1")
	t.Run("fails after serve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddInternalInterface(nil, netip.Addr{}))
	})
	t.Run("single set works", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
	})
	t.Run("double set fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
		assert.Error(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
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
	l := control.LinkEnd{
		IA:   addr.MustParseIA("1-ff00:0:1"),
		Addr: netip.MustParseAddrPort("10.0.0.100:0"),
	}
	r := control.LinkEnd{
		IA:   addr.MustParseIA("1-ff00:0:3"),
		Addr: netip.MustParseAddrPort("10.0.0.200:0"),
	}
	nobfd := control.BFD{Disable: ptr.To(true)}
	t.Run("fails after serve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl), l, r, nobfd))
	})
	t.Run("setting nil conn is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddExternalInterface(42, nil, l, r, nobfd))
	})
	t.Run("setting blank src is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl),
			control.LinkEnd{}, r, nobfd))
	})
	t.Run("setting blank dst is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl),
			l, control.LinkEnd{}, nobfd))
	})
	t.Run("normal add works", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t,
			d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl), l, r, nobfd))
		assert.NoError(t,
			d.AddExternalInterface(45, mock_router.NewMockBatchConn(ctrl), l, r, nobfd))
	})
	t.Run("overwrite fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t,
			d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl), l, r, nobfd))
		assert.Error(t,
			d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl), l, r, nobfd))
	})
}

func TestDataPlaneAddSVC(t *testing.T) {
	t.Run("succeeds after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.NoError(t, d.AddSvc(addr.SvcCS, netip.AddrPortFrom(netip.IPv4Unspecified(), 0)))
	})
	t.Run("adding empty value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddSvc(addr.SvcCS, netip.AddrPort{}))
	})
	t.Run("normal set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, netip.AddrPortFrom(netip.IPv4Unspecified(), 0)))
		assert.NoError(t, d.AddSvc(addr.SvcDS, netip.AddrPortFrom(netip.IPv4Unspecified(), 0)))
	})
	t.Run("set multiple times works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, netip.AddrPortFrom(netip.IPv4Unspecified(), 0)))
		assert.NoError(t, d.AddSvc(addr.SvcCS, netip.AddrPortFrom(netip.IPv4Unspecified(), 0)))
	})
}

func TestDataPlaneAddNextHop(t *testing.T) {
	l := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	r := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	nilAddrPort := netip.AddrPort{}

	nobfd := control.BFD{Disable: ptr.To(true)}

	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddNextHop(45, l, r, nobfd, ""))
	})
	t.Run("setting nil dst is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddNextHop(45, l, nilAddrPort, nobfd, ""))
	})
	t.Run("setting nil src is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddNextHop(45, nilAddrPort, r, nobfd, ""))
	})
	t.Run("normal add works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddNextHop(45, l, r, nobfd, ""))
		assert.NoError(t, d.AddNextHop(43, l, r, nobfd, ""))
	})
	t.Run("overwrite fails", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddNextHop(45, l, r, nobfd, ""))
		assert.Error(t, d.AddNextHop(45, l, r, nobfd, ""))
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
				ret := &router.DataPlane{Metrics: metrics}
				key := []byte("testkey_xxxxxxxx")
				local := addr.MustParseIA("1-ff00:0:110")

				totalCount := 10
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mInternal.EXPECT().WriteBatch(gomock.Any(), 0).DoAndReturn(
					func(ms underlayconn.Messages, flags int) (int, error) {
						if totalCount == 0 {
							t.Fail()
							return 0, nil
						}
						for _, msg := range ms {
							want := bytes.Repeat([]byte("actualpayloadbytes"), 10-totalCount)
							if len(msg.Buffers[0]) != len(want)+84 {
								return 1, nil
							}
							totalCount--
							if totalCount == 0 {
								done <- struct{}{}
							}
						}
						return len(ms), nil
					}).AnyTimes()
				_ = ret.AddInternalInterface(mInternal, netip.Addr{})

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						// 10 scion messages to external
						for i := 0; i < totalCount; i++ {
							spkt, dpath := prepBaseMsg(time.Now())
							spkt.DstIA = local
							spkt.RawDstAddr = []byte{192, 168, 1, 1}
							dpath.HopFields = []path.HopField{
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

							// IMPORTANT: We don't actually include a SCION/UDP Header.
							// However, prepBaseMsg does pretend that there's a SCIONUDP Header.
							// Remove that. Since the removal of the dispatcher, the router snoops
							// into L4 and would mistake our payload for a broken SCION/UDP header.
							spkt.NextHdr = slayers.L4None

							err := gopacket.SerializeLayers(buffer,
								gopacket.SerializeOptions{FixLengths: true},
								spkt, gopacket.Payload(payload))

							require.NoError(t, err)
							raw := buffer.Bytes()
							copy(m[i].Buffers[0], raw)
							m[i].N = len(raw)
							m[i].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
						}
						return 10, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()
				l := control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:1"),
					Addr: netip.MustParseAddrPort("10.0.0.100:0"),
				}
				r := control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:3"),
					Addr: netip.MustParseAddrPort("10.0.0.200:0"),
				}
				nobfd := control.BFD{Disable: ptr.To(true)}

				_ = ret.AddExternalInterface(1, mExternal, l, r, nobfd)

				_ = ret.SetIA(local)
				_ = ret.SetKey(key)
				return ret
			},
		},
		"bfd bootstrap internal session": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}

				postInternalBFD := func(id layers.BFDDiscriminator, src netip.AddrPort) []byte {
					scn := &slayers.SCION{
						NextHdr:  slayers.L4BFD,
						PathType: empty.PathType,
						Path:     &empty.Path{},
					}
					bfdL := &layers.BFD{
						Version:           1,
						DetectMultiplier:  layers.BFDDetectMultiplier(2),
						MyDiscriminator:   id,
						YourDiscriminator: 0,
					}

					_ = scn.SetSrcAddr(addr.HostIP(src.Addr()))
					buffer := gopacket.NewSerializeBuffer()
					_ = gopacket.SerializeLayers(buffer,
						gopacket.SerializeOptions{FixLengths: true}, scn, bfdL)
					return buffer.Bytes()
				}

				mtx := sync.Mutex{}
				expectRemoteDiscriminators := map[layers.BFDDiscriminator]struct{}{}
				routers := map[netip.AddrPort][]uint16{
					netip.MustParseAddrPort("10.0.200.200:0"): {2, 3},
					netip.MustParseAddrPort("10.0.200.201:0"): {4},
				}

				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						i := 0
						for k := range routers { // post a BFD from each neighbor router
							disc := layers.BFDDiscriminator(i)
							raw := postInternalBFD(disc, k)
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
				mInternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).DoAndReturn(
					func(msgs underlayconn.Messages, _ int) (int, error) {
						pkt := gopacket.NewPacket(msgs[0].Buffers[0],
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
				mInternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				local := netip.MustParseAddrPort("10.0.200.100:0")
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, netip.Addr{})
				for remote, ifIDs := range routers {
					for _, ifID := range ifIDs {
						_ = ret.AddNextHop(ifID, local, remote, bfd(), "")
					}
				}
				return ret
			},
		},
		"bfd sender internal": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				localAddr := netip.MustParseAddrPort("10.0.200.100:0")
				remoteAddr := netip.MustParseAddrPort("10.0.200.200:0")
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).DoAndReturn(
					func(msgs underlayconn.Messages, _ int) (int, error) {
						pkt := gopacket.NewPacket(msgs[0].Buffers[0],
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
							if a.IP() != localAddr.Addr() {
								return 1, nil
							}

							b, err := s.DstAddr()
							if err != nil {
								return 1, nil
							}
							if b.IP() != remoteAddr.Addr() {
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
				_ = ret.AddInternalInterface(mInternal, netip.Addr{})
				_ = ret.AddNextHop(3, localAddr, remoteAddr, bfd(), "")
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
				mExternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).DoAndReturn(
					func(msgs underlayconn.Messages, _ int) (int, error) {
						pkt := gopacket.NewPacket(msgs[0].Buffers[0],
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
				mExternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				local := control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:1"),
					Addr: netip.MustParseAddrPort("10.0.0.100:0"),
				}
				remote := control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:3"),
					Addr: netip.MustParseAddrPort("10.0.0.200:0"),
				}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, netip.Addr{})
				_ = ret.AddExternalInterface(ifID, mExternal, local, remote, bfd())
				return ret
			},
		},
		"bfd bootstrap external session": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}

				postExternalBFD := func(id layers.BFDDiscriminator, fromIfID uint16) []byte {
					scn := &slayers.SCION{
						NextHdr:  slayers.L4BFD,
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
						m[0].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
						return 1, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mExternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).DoAndReturn(
					func(msgs underlayconn.Messages, _ int) (int, error) {
						pkt := gopacket.NewPacket(msgs[0].Buffers[0],
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
				mExternal.EXPECT().WriteBatch(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				local := control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:1"),
					Addr: netip.MustParseAddrPort("10.0.0.100:0"),
				}
				remote := control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:3"),
					Addr: netip.MustParseAddrPort("10.0.0.200:0"),
				}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, netip.Addr{})
				_ = ret.AddExternalInterface(1, mExternal, local, remote, bfd())
				return ret
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runConfig := &router.RunConfig{
				NumProcessors:         8,
				BatchSize:             256,
				NumSlowPathProcessors: 1,
			}
			ch := make(chan struct{})
			dp := tc.prepareDP(ctrl, ch)
			errors := make(chan error)
			ctx, cancelF := context.WithCancel(context.Background())
			defer cancelF()
			go func() {
				errors <- dp.Run(ctx, runConfig)
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

// Returns true if we expect no output packet.
// That includes the processing of BFD packets.
func discarded(t *testing.T, disp router.Disposition) {
	require.Equal(t, disp, router.PDiscard)
}

// Returns trues if we expect an output packet.
// That includes slowpath processing.
func notDiscarded(t *testing.T, disp router.Disposition) {
	require.NotEqual(t, disp, router.PDiscard)
}

func TestProcessPkt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	otherKey := []byte("testkey_yyyyyyyy")
	now := time.Now()
	epicTS, err := libepic.CreateTimestamp(now, now)
	require.NoError(t, err)

	// ProcessPacket assumes some pre-conditions:
	// * The ingress interface has to exist. This fake map is good for most test cases.
	//   Others need a custom one.
	// * InternalNextHops may not be nil. Empty is ok (sufficient unless testing AS transit).
	fakeExternalInterfaces := map[uint16]router.BatchConn{1: nil, 2: nil, 3: nil}
	fakeInternalNextHops := map[uint16]netip.AddrPort{}

	testCases := map[string]struct {
		mockMsg    func(bool) *router.Packet
		prepareDP  func(*gomock.Controller) *router.DataPlane
		assertFunc func(*testing.T, router.Disposition)
	}{
		"inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, dpath := prepBaseMsg(now)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])

				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: dstUDPPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"inbound_longpath": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, dpath := prepBaseMsg(now)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}

				// Everything is the same a in the inbound test, except that we tossed in
				// 64 extra hops and two extra segments.
				dpath.Base.PathMeta.CurrHF = 2
				dpath.Base.PathMeta.SegLen = [3]uint8{24, 24, 17}
				dpath.InfoFields = append(
					dpath.InfoFields,
					path.InfoField{SegID: 0x112, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					path.InfoField{SegID: 0x113, ConsDir: true, Timestamp: util.TimeToSecs(now)},
				)
				dpath.Base.NumINF = 3
				dpath.Base.NumHops = 65
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])

				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: discarded,
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
					nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, dpath := prepBaseMsg(now)
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []path.HopField{
					{ConsIngress: 0, ConsEgress: 1},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 41, ConsEgress: 40},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.HopFields[0].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[0])
				ingress := uint16(0)
				egress := uint16(0)
				if afterProcessing {
					_ = dpath.IncPath()
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].Mac)
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, dpath := prepBaseMsg(now)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 2},
					{ConsIngress: 40, ConsEgress: 41},
				}
				dpath.Base.PathMeta.CurrHF = 1
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					_ = dpath.IncPath()
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						2: topology.Parent,
						1: topology.Child,
					}, nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, dpath := prepBaseMsg(now)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 2, ConsEgress: 1},
					{ConsIngress: 40, ConsEgress: 41},
				}
				dpath.Base.PathMeta.CurrHF = 1
				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					require.NoError(t, dpath.IncPath())
					egress = 2
				} else {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit peering consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				// Story: the packet just left segment 0 which ends at
				// (peering) hop 0 and is landing on segment 1 which
				// begins at (peering) hop 1. We do not care what hop 0
				// looks like. The forwarding code is looking at hop 1 and
				// should leave the message in shape to be processed at hop 2.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  1,
							CurrINF: 1,
							SegLen:  [3]uint8{1, 2, 0},
						},
						NumINF:  2,
						NumHops: 3,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 40, ConsEgress: 41},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the second one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[1])
				dpath.HopFields[2].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[1], dpath.HopFields[2])
				ingress := uint16(1) // from peering link
				egress := uint16(0)
				if afterProcessing {
					_ = dpath.IncPath()

					// ... The SegID accumulator wasn't updated from HF[1],
					// it is still the same. That is the key behavior.
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit peering non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				// Story: the packet lands on the last (peering) hop of
				// segment 0. After processing, the packet is ready to
				// be processed by the first (peering) hop of segment 1.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  1,
							CurrINF: 0,
							SegLen:  [3]uint8{2, 1, 0},
						},
						NumINF:  2,
						NumHops: 3,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 40, ConsEgress: 41},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (0 and 1) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the first one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[0].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[0], dpath.HopFields[0])
				dpath.HopFields[1].Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1])

				// We're going against construction order, so the accumulator
				// value is that of the previous hop in traversal order. The
				// story starts with the packet arriving at hop 1, so the
				// accumulator value must match hop field 0. In this case,
				// it is identical to that for hop field 1, which we made
				// identical to the original SegID. So, we're all set.
				ingress := uint16(2) // from child link
				egress := uint16(0)
				if afterProcessing {
					_ = dpath.IncPath()

					// The SegID should not get updated on arrival. If it is, then MAC validation
					// of HF1 will fail. Otherwise, this isn't visible because we changed segment.
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"peering consdir downstream": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				// Story: the packet just left hop 1 (the first hop
				// of peering down segment 1) and is processed at hop 2
				// which is not a peering hop.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  2,
							CurrINF: 1,
							SegLen:  [3]uint8{1, 3, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 40, ConsEgress: 41},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 50, ConsEgress: 51},
						// There has to be a 4th hop to make
						// the 3rd router agree that the packet
						// is not at destination yet.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The router shouldn't need to
				// know this or do anything special. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[1], dpath.HopFields[1])
				dpath.HopFields[2].Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[2])
				ingress := uint16(1)
				egress := uint16(0)
				// The SegID we provide is that of HF[2] which happens to be SEG[1]'s SegID,
				// so, already set for the before-processing state.
				if afterProcessing {
					_ = dpath.IncPath()

					// ... The SegID accumulator should have been updated.
					dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"peering non consdir upstream": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				// Story: the packet lands on the second (non-peering) hop of
				// segment 0 (a peering segment). After processing, the packet
				// is ready to be processed by the third (peering) hop of segment 0.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  1,
							CurrINF: 0,
							SegLen:  [3]uint8{3, 1, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 40, ConsEgress: 41},
						{ConsIngress: 50, ConsEgress: 51},
						// The second segment (4th hop) has to be
						// there but the packet isn't processed
						// at that hop for this test.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The SegID accumulator value can
				// be anything (it comes from the parent hop of HF[1]
				// in the original beaconned segment, which is not in
				// the path). So, we use one from an info field because
				// computeMAC makes that easy.
				dpath.HopFields[1].Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1])
				dpath.HopFields[2].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[0], dpath.HopFields[2])

				ingress := uint16(2) // from child link
				egress := uint16(0)
				if afterProcessing {
					_ = dpath.IncPath()

					// After-processing, the SegID should have been updated
					// (on ingress) to be that of HF[1], which happens to be
					// the Segment's SegID. That is what we already have as
					// we only change it in the before-processing version
					// of the packet.
					egress = 1
				} else {
					// We're going against construction order, so the before-processing accumulator
					// value is that of the previous hop in traversal order. The story starts with
					// the packet arriving at hop 1, so the accumulator value must match hop field
					// 0, which derives from hop field[1]. HopField[0]'s MAC is not checked during
					// this test.
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"astransit direct": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						// Interface 3 isn't in the external interfaces of this router
						// another router has it.
					},
					map[uint16]topology.LinkType{
						1: topology.Core,
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]netip.AddrPort{
						uint16(3): netip.MustParseAddrPort("10.0.200.200:30043"),
					}, nil, addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, dpath := prepBaseMsg(now)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 3},
					{ConsIngress: 50, ConsEgress: 51},
				}
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0) // Internal forward to the egress router
				if afterProcessing {
					dstAddr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"astransit xover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(51): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]netip.AddrPort{
						uint16(3): netip.MustParseAddrPort("10.0.200.200:30043"),
					}, nil, addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 0,
							CurrHF:  1,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 0}, // Src
						{ConsIngress: 0, ConsEgress: 51}, // IA 110
						{ConsIngress: 3, ConsEgress: 0},  // IA 110
						{ConsIngress: 0, ConsEgress: 1},  // Dst
					},
				}
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2])

				var dstAddr *net.UDPAddr
				ingress := uint16(51) // == consEgress, bc non-consdir
				egress := uint16(0)   // Cross-over. The egress happens in the next segment.
				if afterProcessing {
					dpath.PathMeta.CurrHF++
					dpath.PathMeta.CurrINF++
					dstAddr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				} else {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
				}

				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"svc": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					map[addr.SVC][]netip.AddrPort{
						addr.SvcCS: {
							netip.AddrPortFrom(
								netip.MustParseAddr("10.0.200.200"),
								uint16(dstUDPPort),
							),
						},
					},
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, dpath := prepBaseMsg(now)
				_ = spkt.SetDstAddr(addr.MustParseHost("CS"))
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dstAddr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(),
						Port: dstUDPPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"onehop inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					fakeExternalInterfaces,
					nil,
					mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.SVC][]netip.AddrPort{
						addr.SvcCS: {
							netip.AddrPortFrom(
								netip.MustParseAddr("172.0.2.10"),
								uint16(dstUDPPort),
							),
						},
					},
					addr.MustParseIA("1-ff00:0:110"),
					map[uint16]addr.IA{
						uint16(1): addr.MustParseIA("1-ff00:0:111"),
					}, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:111")
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: 0x100,
					},
					FirstHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 0,
						ConsEgress:  21,
						Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
				}
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dpath.SecondHop = path.HopField{
						ExpTime:     63,
						ConsIngress: 1,
					}
					dpath.SecondHop.Mac = computeMAC(t, key, dpath.Info, dpath.SecondHop)

					sp, err := dpath.ToSCIONDecoded()
					require.NoError(t, err)
					_, err = sp.Reverse()
					require.NoError(t, err)

					dstAddr = &net.UDPAddr{
						IP:   net.ParseIP("172.0.2.10").To4(), // Else we get a v4mapped address.
						Port: dstUDPPort,
					}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"onehop inbound invalid src": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					fakeExternalInterfaces,
					nil, nil,
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"),
					map[uint16]addr.IA{
						uint16(1): addr.MustParseIA("1-ff00:0:111"),
					}, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110") // sneaky
				spkt.DstIA = addr.MustParseIA("1-ff00:0:111")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
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
						Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
				}
				ingress := uint16(2)
				egress := uint16(21)
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: discarded,
		},
		"reversed onehop outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					nil,
					mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					map[addr.SVC][]netip.AddrPort{
						addr.SvcCS: {
							netip.AddrPortFrom(
								netip.MustParseAddr("172.0.2.10"),
								uint16(dstUDPPort),
							),
						},
					},
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = scion.PathType
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: util.TimeToSecs(time.Now()),
					},
					FirstHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 0,
						ConsEgress:  21,
						Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
					SecondHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 1,
					},
				}
				dpath.SecondHop.Mac = computeMAC(t, key, dpath.Info, dpath.SecondHop)
				sp, err := dpath.ToSCIONDecoded()
				require.NoError(t, err)
				require.NoError(t, sp.IncPath())
				p, err := sp.Reverse()
				require.NoError(t, err)
				sp = p.(*scion.Decoded)

				ingress := uint16(0)
				egress := uint16(0)
				if afterProcessing {
					require.NoError(t, sp.IncPath())
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, sp), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"onehop outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					nil,
					mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"),
					map[uint16]addr.IA{
						uint16(2): addr.MustParseIA("1-ff00:0:111"),
					}, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				spkt.DstIA = addr.MustParseIA("1-ff00:0:111")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: 0x100,
					},
					FirstHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 0,
						ConsEgress:  2,
					},
				}
				dpath.FirstHop.Mac = computeMAC(t, key, dpath.Info, dpath.FirstHop)

				ingress := uint16(0)
				egress := uint16(0)
				if afterProcessing {
					dpath.Info.UpdateSegID(dpath.FirstHop.Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"epic inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)

				prepareEpicCrypto(t, spkt, epicpath, dpath, key)
				return toIP(t, spkt, epicpath, afterProcessing, 1, 0)
			},
			assertFunc: notDiscarded,
		},
		"epic malformed path": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)
				prepareEpicCrypto(t, spkt, epicpath, dpath, key)

				// Wrong path type
				return toIP(t, spkt, &scion.Decoded{}, afterProcessing, 1, 0)
			},
			assertFunc: discarded,
		},
		"epic invalid timestamp": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)

				// Invalid timestamp
				epicpath.PktID.Timestamp = epicpath.PktID.Timestamp + 250000

				prepareEpicCrypto(t, spkt, epicpath, dpath, key)
				return toIP(t, spkt, epicpath, afterProcessing, 1, 0)
			},
			assertFunc: discarded,
		},
		"epic invalid LHVF": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *router.Packet {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)
				prepareEpicCrypto(t, spkt, epicpath, dpath, key)

				// Invalid LHVF
				epicpath.LHVF = []byte{0, 0, 0, 0}

				return toIP(t, spkt, epicpath, afterProcessing, 1, 0)
			},
			assertFunc: discarded,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP(ctrl)
			pkt, want := tc.mockMsg(false), tc.mockMsg(true)
			disp := dp.ProcessPkt(pkt)
			tc.assertFunc(t, disp)
			if disp == router.PDiscard {
				return
			}
			assert.Equal(t, want, pkt)
		})
	}
}

func toBytes(t *testing.T, spkt *slayers.SCION, dpath path.Path) []byte {
	t.Helper()
	spkt.Path = dpath
	buffer := gopacket.NewSerializeBuffer()
	scionudpLayer := &slayers.UDP{}
	scionudpLayer.SrcPort = uint16(srcUDPPort)
	scionudpLayer.DstPort = uint16(dstUDPPort)
	scionudpLayer.SetNetworkLayerForChecksum(spkt)
	payload := []byte("actualpayloadbytes")
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		spkt, scionudpLayer, gopacket.Payload(payload))
	require.NoError(t, err)
	return buffer.Bytes()
}

func prepBaseMsg(now time.Time) (*slayers.SCION, *scion.Decoded) {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        addr.MustParseIA("4-ff00:0:411"),
		SrcIA:        addr.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
		PayloadLen:   26, // scionudpLayer + len("actualpayloadbytes")
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
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []path.HopField{},
	}
	return spkt, dpath
}

func prepEpicMsg(t *testing.T, afterProcessing bool, key []byte,
	epicTS uint32, now time.Time) (*slayers.SCION, *epic.Path, *scion.Decoded) {

	spkt, dpath := prepBaseMsg(now)
	spkt.PathType = epic.PathType

	spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
	dpath.HopFields = []path.HopField{
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
	require.NoError(t, spkt.SetSrcAddr(addr.MustParseHost("10.0.200.200")))

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
		spkt, dpath.InfoFields[0].Timestamp, nil)
	require.NoError(t, err)
	copy(epicpath.LHVF, macLast)
}

func toIP(
	t *testing.T,
	spkt *slayers.SCION,
	path path.Path,
	afterProcessing bool,
	ingress, egress uint16,
) *router.Packet {

	// Encapsulate in IPv4
	var dstAddr *net.UDPAddr
	dst := addr.MustParseHost("10.0.100.100")
	require.NoError(t, spkt.SetDstAddr(dst))
	if afterProcessing {
		dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: dstUDPPort}
	} else {
		egress = 0
	}
	return router.NewPacket(toBytes(t, spkt, path), nil, dstAddr, ingress, egress)
}

func computeMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf, nil)
}

func computeFullMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) []byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.FullMAC(mac, info, hf, nil)
}

func bfd() control.BFD {
	return control.BFD{
		Disable:               ptr.To(false),
		DetectMult:            3,
		DesiredMinTxInterval:  1 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
	}
}
