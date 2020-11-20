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

package control_test

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
)

func TestEngineRun(t *testing.T) {
	t.Run("double run", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engine := &control.Engine{
			SessionConfigs:          nil,
			RoutingTable:            mock_control.NewMockRoutingTable(ctrl),
			PathMonitor:             mock_control.NewMockPathMonitor(ctrl),
			ProbeConnFactory:        mock_control.NewMockPacketConnFactory(ctrl),
			DataplaneSessionFactory: mock_control.NewMockDataplaneSessionFactory(ctrl),
		}

		go func() {
			engine.Run()
		}()
		time.Sleep(50 * time.Millisecond)
		err := engine.Run()
		assert.Error(t, err)
	})

	t.Run("nil routing table", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engine := &control.Engine{
			PathMonitor:             mock_control.NewMockPathMonitor(ctrl),
			ProbeConnFactory:        mock_control.NewMockPacketConnFactory(ctrl),
			DataplaneSessionFactory: mock_control.NewMockDataplaneSessionFactory(ctrl),
		}
		err := engine.Run()
		assert.Error(t, err)
	})

	t.Run("nil path monitor", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engine := &control.Engine{
			SessionConfigs:          nil,
			RoutingTable:            mock_control.NewMockRoutingTable(ctrl),
			ProbeConnFactory:        mock_control.NewMockPacketConnFactory(ctrl),
			DataplaneSessionFactory: mock_control.NewMockDataplaneSessionFactory(ctrl),
		}
		err := engine.Run()
		assert.Error(t, err)
	})

	t.Run("nil probe conn factory", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engine := &control.Engine{
			SessionConfigs:          nil,
			RoutingTable:            mock_control.NewMockRoutingTable(ctrl),
			PathMonitor:             mock_control.NewMockPathMonitor(ctrl),
			DataplaneSessionFactory: mock_control.NewMockDataplaneSessionFactory(ctrl),
		}
		err := engine.Run()
		assert.Error(t, err)
	})

	t.Run("nil dataplane session factory", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engine := &control.Engine{
			SessionConfigs:   nil,
			RoutingTable:     mock_control.NewMockRoutingTable(ctrl),
			PathMonitor:      mock_control.NewMockPathMonitor(ctrl),
			ProbeConnFactory: mock_control.NewMockPacketConnFactory(ctrl),
		}
		err := engine.Run()
		assert.Error(t, err)
	})

	t.Run("close before run", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engine := &control.Engine{
			SessionConfigs:          nil,
			RoutingTable:            mock_control.NewMockRoutingTable(ctrl),
			PathMonitor:             mock_control.NewMockPathMonitor(ctrl),
			ProbeConnFactory:        mock_control.NewMockPacketConnFactory(ctrl),
			DataplaneSessionFactory: mock_control.NewMockDataplaneSessionFactory(ctrl),
		}

		err := engine.Close()
		require.NoError(t, err)
		err = engine.Run()
		assert.NoError(t, err)
	})
}
