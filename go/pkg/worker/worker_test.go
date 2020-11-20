// Copyright 2020 Anapaya Systems

package worker_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/worker"
)

func TestWorker(t *testing.T) {
	t.Run("double run", func(t *testing.T) {
		t.Parallel()
		worker := &testWorker{}

		go func() {
			worker.Run()
		}()
		time.Sleep(50 * time.Millisecond)
		err := worker.Run()
		assert.Error(t, err)
	})

	t.Run("double run nil worker", func(t *testing.T) {
		t.Parallel()
		worker := &nilTestWorker{}

		go func() {
			worker.Run()
		}()
		time.Sleep(50 * time.Millisecond)
		err := worker.Run()
		assert.Error(t, err)
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
	return w.wb.RunWrapper(w.setup, w.run)
}

func (w *testWorker) setup() error {
	return nil
}

func (w *testWorker) run() error {
	<-w.wb.GetDoneChan()
	return nil
}

func (w *testWorker) Close() error {
	return w.wb.CloseWrapper(w.close)
}

func (w *testWorker) close() error {
	return nil
}

type nilTestWorker struct {
	wb worker.Base
}

func (w *nilTestWorker) Run() error {
	return w.wb.RunWrapper(nil, nil)
}

func (w *nilTestWorker) Close() error {
	return w.wb.CloseWrapper(nil)
}
