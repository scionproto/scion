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

package worker_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/worker"
)

func TestWorker(t *testing.T) {
	t.Run("double run", func(t *testing.T) {
		t.Parallel()
		worker := &testWorker{}

		var bg errgroup.Group
		bg.Go(worker.Run)
		time.Sleep(50 * time.Millisecond)
		err := worker.Run()
		assert.Error(t, err)
		assert.NoError(t, worker.Close())
		assert.NoError(t, bg.Wait())
	})

	t.Run("double run nil worker", func(t *testing.T) {
		t.Parallel()
		worker := &nilTestWorker{}

		var bg errgroup.Group
		bg.Go(worker.Run)
		time.Sleep(50 * time.Millisecond)
		err := worker.Run()
		assert.Error(t, err)
		assert.NoError(t, worker.Close())
		assert.NoError(t, bg.Wait())
	})

	t.Run("close before run", func(t *testing.T) {
		t.Parallel()
		worker := &testWorker{}

		err := worker.Close()
		require.NoError(t, err)

		err = worker.Run()
		assert.NoError(t, err)
	})

	t.Run("close before run nil worker", func(t *testing.T) {
		t.Parallel()
		worker := &nilTestWorker{}

		err := worker.Close()
		require.NoError(t, err)

		err = worker.Run()
		assert.NoError(t, err)
	})

	t.Run("double close", func(t *testing.T) {
		t.Parallel()
		worker := &testWorker{}

		err := worker.Close()
		require.NoError(t, err)

		err = worker.Close()
		require.NoError(t, err)
	})

	t.Run("close after run", func(t *testing.T) {
		t.Parallel()
		worker := &testWorker{}

		go func() {
			err := worker.Run()
			require.NoError(t, err)
		}()
		time.Sleep(50 * time.Millisecond)
		closedCh := make(chan struct{})
		go func() {
			err := worker.Close()
			require.NoError(t, err)
			close(closedCh)
		}()
		xtest.AssertReadReturnsBefore(t, closedCh, time.Second)
	})
}

type testWorker struct {
	wb worker.Base
}

func (w *testWorker) Run() error {
	return w.wb.RunWrapper(context.Background(), w.setup, w.run)
}

func (w *testWorker) setup(ctx context.Context) error {
	return nil
}

func (w *testWorker) run(ctx context.Context) error {
	<-w.wb.GetDoneChan()
	return nil
}

func (w *testWorker) Close() error {
	return w.wb.CloseWrapper(context.Background(), w.close)
}

func (w *testWorker) close(ctx context.Context) error {
	return nil
}

type nilTestWorker struct {
	wb worker.Base
}

func (w *nilTestWorker) Run() error {
	return w.wb.RunWrapper(context.Background(), nil, nil)
}

func (w *nilTestWorker) Close() error {
	return w.wb.CloseWrapper(context.Background(), nil)
}
