// Copyright 2021 Anapaya Systems
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

package routemgr_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/routemgr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
)

func TestSingleDeviceManager(t *testing.T) {
	t.Run("nil opener", func(t *testing.T) {
		t.Parallel()
		m := routemgr.SingleDeviceManager{}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, handle)
		assert.NotNil(t, err)
	})

	t.Run("get IA", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle.Close())
	})

	t.Run("get different IAs", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle1, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)
		handle2, err := m.Get(xtest.MustParseIA("1-ff00:0:2"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle1.Close())
		assert.Nil(t, handle2.Close())
	})

	t.Run("get same IA", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle1, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)
		handle2, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle1.Close())
		assert.Nil(t, handle2.Close())
	})

	t.Run("failed open", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).
			Return(nil, serrors.New("test error"))

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, handle)
		assert.NotNil(t, err)
	})

	t.Run("failed close", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close().Return(serrors.New("test error"))
		assert.NotNil(t, handle.Close())
	})

	t.Run("too many close", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle.Close())
		assert.NotNil(t, handle.Close())
	})

	t.Run("forward Handle APIs", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		t.Run("read", func(t *testing.T) {
			b := make([]byte, 8)
			mockDeviceHandle.EXPECT().Read(b).Return(8, nil)

			n, err := handle.Read(b)
			assert.Equal(t, 8, n)
			assert.Nil(t, err)
		})

		t.Run("write", func(t *testing.T) {
			b := make([]byte, 8)
			mockDeviceHandle.EXPECT().Write(b).Return(8, nil)

			n, err := handle.Write(b)
			assert.Equal(t, 8, n)
			assert.Nil(t, err)
		})

		t.Run("add route", func(t *testing.T) {
			r := &control.Route{}
			mockDeviceHandle.EXPECT().AddRoute(r).Return(nil)

			err := handle.AddRoute(r)
			assert.Nil(t, err)
		})

		t.Run("delete route", func(t *testing.T) {
			r := &control.Route{}
			mockDeviceHandle.EXPECT().DeleteRoute(r).Return(nil)

			err := handle.DeleteRoute(r)
			assert.Nil(t, err)
		})
	})

	t.Run("Handle APIs after close", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle.Close())

		t.Run("read", func(t *testing.T) {
			b := make([]byte, 8)
			n, err := handle.Read(b)
			assert.Equal(t, 0, n)
			assert.True(t, errors.Is(err, control.ObjectDestroyedError))
		})

		t.Run("add route", func(t *testing.T) {
			err := handle.AddRoute(&control.Route{})
			assert.True(t, errors.Is(err, control.ObjectDestroyedError))
		})
	})

	t.Run("close while executing IO APIs", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()

		ioLaunchedBarrier := make(chan int)
		handleClosedBarrier := make(chan int)

		b := make([]byte, 8)
		mockDeviceHandle.EXPECT().Read(b).DoAndReturn(
			func(b []byte) (int, error) {
				close(ioLaunchedBarrier)
				<-handleClosedBarrier
				return 4, serrors.New("interrupted")
			},
		)

		go func() {
			<-ioLaunchedBarrier
			handle.Close()
			close(handleClosedBarrier)
		}()

		n, err := handle.Read(b)
		assert.Equal(t, 4, n)
		assert.True(t, errors.Is(err, control.ObjectDestroyedError))
	})

	t.Run("close while executing routing APIs", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()

		routeLaunchedBarrier := make(chan int)
		handleClosedBarrier := make(chan int)

		r := &control.Route{}
		mockDeviceHandle.EXPECT().AddRoute(r).DoAndReturn(
			func(*control.Route) error {
				close(routeLaunchedBarrier)
				<-handleClosedBarrier
				return serrors.New("interrupted")
			},
		)

		go func() {
			<-routeLaunchedBarrier
			handle.Close()
			close(handleClosedBarrier)
		}()

		err = handle.AddRoute(r)
		assert.True(t, errors.Is(err, control.ObjectDestroyedError))
	})

	t.Run("get IA, close, get same IA again", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDeviceHandle1 := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle1, nil)

		m := routemgr.SingleDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle1, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle1.EXPECT().Close()
		assert.Nil(t, handle1.Close())

		mockDeviceHandle2 := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener.EXPECT().Open(gomock.Any()).Return(mockDeviceHandle2, nil)

		handle2, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, err)

		mockDeviceHandle2.EXPECT().Close()
		assert.Nil(t, handle2.Close())
	})
}

func TestFixedTunnelName(t *testing.T) {
	namer := routemgr.FixedTunnelName("foo")
	assert.Equal(t, "foo", namer(xtest.MustParseIA("1-ff00:0:1")))
}

func TestBase32TunnelName(t *testing.T) {
	testCases := map[string]*struct {
		IA   addr.IA
		Name string
	}{
		"1-ff00:0:1": {
			IA:   xtest.MustParseIA("1-ff00:0:1"),
			Name: "s.AAA76AAAAAAAC",
		},
		"1-ff00:0:2": {
			IA:   xtest.MustParseIA("1-ff00:0:2"),
			Name: "s.AAA76AAAAAAAE",
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.Name, routemgr.Base32TunnelName(tc.IA))
		})
	}
}

func TestMultiDeviceManager(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		m := routemgr.MultiDeviceManager{}

		handle, err := m.Get(xtest.MustParseIA("1-ff00:0:1"))
		assert.Nil(t, handle)
		assert.NotNil(t, err)
	})

	t.Run("get IA", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(ia)
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		handle.Close()
	})

	t.Run("get different IAs", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia1 := xtest.MustParseIA("1-ff00:0:1")
		ia2 := xtest.MustParseIA("1-ff00:0:2")

		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceHandle1 := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener.EXPECT().Open(ia1).Return(mockDeviceHandle1, nil)
		mockDeviceHandle2 := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener.EXPECT().Open(ia2).Return(mockDeviceHandle2, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle1, err := m.Get(ia1)
		assert.Nil(t, err)
		handle2, err := m.Get(ia2)
		assert.Nil(t, err)

		mockDeviceHandle1.EXPECT().Close()
		assert.Nil(t, handle1.Close())

		mockDeviceHandle2.EXPECT().Close()
		assert.Nil(t, handle2.Close())
	})

	t.Run("get same IA", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle1, err := m.Get(ia)
		assert.Nil(t, err)
		handle2, err := m.Get(ia)
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle1.Close())
		assert.Nil(t, handle2.Close())
	})

	t.Run("failed open", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(nil, serrors.New("test error"))

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(ia)
		assert.Nil(t, handle)
		assert.NotNil(t, err)
	})

	t.Run("failed close", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(ia)
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close().Return(serrors.New("test error"))
		assert.NotNil(t, handle.Close())
	})

	t.Run("too many close", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(ia)
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle.Close())
		assert.NotNil(t, handle.Close())
	})

	t.Run("closing handles does not leak memory", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(ia)
		assert.NotNil(t, handle)
		assert.Nil(t, err)

		mockDeviceHandle.EXPECT().Close()
		assert.Nil(t, handle.Close())

		assert.Zero(t, m.Size())
	})

	t.Run("forward Handle APIs", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceHandle := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle, err := m.Get(ia)
		assert.Nil(t, err)

		t.Run("read", func(t *testing.T) {
			b := make([]byte, 8)
			mockDeviceHandle.EXPECT().Read(b).Return(8, nil)

			n, err := handle.Read(b)
			assert.Equal(t, 8, n)
			assert.Nil(t, err)
		})

		t.Run("write", func(t *testing.T) {
			b := make([]byte, 8)
			mockDeviceHandle.EXPECT().Write(b).Return(8, nil)

			n, err := handle.Write(b)
			assert.Equal(t, 8, n)
			assert.Nil(t, err)
		})

		t.Run("add route", func(t *testing.T) {
			r := &control.Route{}
			mockDeviceHandle.EXPECT().AddRoute(r).Return(nil)

			err := handle.AddRoute(r)
			assert.Nil(t, err)
		})

		t.Run("delete route", func(t *testing.T) {
			r := &control.Route{}
			mockDeviceHandle.EXPECT().DeleteRoute(r).Return(nil)

			err := handle.DeleteRoute(r)
			assert.Nil(t, err)
		})
	})

	t.Run("get IA, close, get same IA again", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ia := xtest.MustParseIA("1-ff00:0:1")

		mockDeviceHandle1 := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener := mock_control.NewMockDeviceOpener(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle1, nil)

		m := routemgr.MultiDeviceManager{
			DeviceOpener: mockDeviceOpener,
		}

		handle1, err := m.Get(ia)
		assert.Nil(t, err)

		mockDeviceHandle1.EXPECT().Close()
		assert.Nil(t, handle1.Close())

		mockDeviceHandle2 := mock_control.NewMockDeviceHandle(ctrl)
		mockDeviceOpener.EXPECT().Open(ia).Return(mockDeviceHandle2, nil)

		handle2, err := m.Get(ia)
		assert.Nil(t, err)

		mockDeviceHandle2.EXPECT().Close()
		assert.Nil(t, handle2.Close())
	})
}
