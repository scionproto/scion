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
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestRemoteMonitor(t *testing.T) {
	ia1 := addr.MustParseIA("1-ff00:0:110")
	ia2 := addr.MustParseIA("1-ff00:0:111")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// runningWatcher represents a watcher that is running.
	type runningWatcher struct {
		Ctx context.Context
		IA  addr.IA
	}

	watcherChan := make(chan runningWatcher, 10)
	watcherFactory := mock_control.NewMockGatewayWatcherFactory(ctrl)
	watcherFactory.EXPECT().New(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, ia addr.IA, _ control.GatewayWatcherMetrics) control.Runner {
			gw := mock_control.NewMockRunner(ctrl)
			gw.EXPECT().Run(gomock.Any()).DoAndReturn(
				func(ctx context.Context) error {
					watcherChan <- runningWatcher{Ctx: ctx, IA: ia}
					<-ctx.Done()
					return nil
				}).AnyTimes()
			return gw
		}).AnyTimes()

	iaChan := make(chan []addr.IA)
	rm := control.RemoteMonitor{
		GatewayWatcherFactory: watcherFactory,
		IAs:                   iaChan,
	}
	go func() {
		err := rm.Run(context.Background())
		require.NoError(t, err)
	}()

	// Add a new IA.
	iaChan <- []addr.IA{ia1}
	watcher1 := <-watcherChan // <--
	require.Equal(t, ia1, watcher1.IA)
	assert.Empty(t, watcherChan)

	// Keep an old IA while adding a new one.
	iaChan <- []addr.IA{ia1, ia2}
	watcher2 := <-watcherChan
	require.Equal(t, ia2, watcher2.IA)
	assert.Empty(t, watcherChan)

	// Remove an IA.
	iaChan <- []addr.IA{ia1}
	// ia2 watcher should be canceled.
	xtest.AssertReadReturnsBefore(t, watcher2.Ctx.Done(), time.Second)
	// ia1 watcher should not.
	require.NoError(t, watcher1.Ctx.Err())

	// Remove remaining IAs.
	rm.Close(context.Background())
	// ia1 watcher should be canceled.
	xtest.AssertReadReturnsBefore(t, watcher1.Ctx.Done(), time.Second)
}
