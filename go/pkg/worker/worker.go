// Copyright 2020 Anapaya Systems

// Package worker contains helpers for working with long-running goroutines that need to be
// destroyed.
package worker

import (
	"sync"

	"github.com/scionproto/scion/go/lib/serrors"
)

// Base provides basic operations for objects designed to run as goroutines that have the following
// properties:
//
// 1. Run starts the worker's task and blocks until the worker has finished or it has been shut down
// via Close.
//
// 2.Close stops a running worker. If called before the worker has started, the worker will skip its
// task. In this case, both Run and Close will return nil.
//
// Base should be added to objects that provide Run and Close methods, and those methods should use
// the runWrapper and closeWrapper decorators to invoke the run and close logic. For an example, see
// the testWorker in this file.
//
// Base ensures that calling Run more than once returns an error, calling Close before a Run cancels
// the run and that Close will wait for Run to finish if it has already started.
//
// If the Run method of the worker spawns additional goroutines, it can use the wg field to add them
// to the wait group. Close will wait on the wg for all of them to finish before returning.
//
// Similarly to the sync primitives on which it relies, Base cannot be copied.
type Base struct {
	mu sync.Mutex
	// runCalled is incremented on the first execution of Run. Future calls will return an error.
	runCalled bool
	// doneChan is closed when the engine needs to shut down.
	doneChan chan struct{}
	// WG is the wait group for goroutines started by a Run call. This can be incremented and
	// decremented inside Run callbacks (n increments should have a matching number of n decrements
	// when Run cleans up after itself). Close will wait on the wait group before returning.
	WG sync.WaitGroup
}

// setupWrapper is used to call a worker's setup and run functions.
//
// The functions are guaranteed to execute only once. Future attempts will return an error.
//
// The setup function and close function share a mutex, guaranteeing they never execute in parallel.
// The run function is not subject to the same constraint.
//
// The return value is the return value of runF (if it executes), or setupF (otherwise).
//
// If setupF or runF are nil, they will be skipped.
func (wb *Base) RunWrapper(setupF func() error, runF func() error) error {
	wb.mu.Lock()
	if err := wb.callSetupLocked(setupF); err != nil {
		wb.mu.Unlock()
		return err
	}
	wb.WG.Add(1)
	defer wb.WG.Done()
	wb.mu.Unlock()

	if runF == nil {
		return nil
	}
	return runF()
}

func (wb *Base) callSetupLocked(setupF func() error) error {
	if wb.runCalled == true {
		return serrors.New("function called more than once")
	}
	wb.runCalled = true

	select {
	case <-wb.getDoneChanLocked():
		// Close already called, do not run setup
		return nil
	default:
		// Close not called yet, run setup
	}

	if setupF == nil {
		return nil
	}
	return setupF()
}

func (wb *Base) closeDoneChanLocked() {
	ch := wb.getDoneChanLocked()
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (wb *Base) GetDoneChan() chan struct{} {
	wb.mu.Lock()
	defer wb.mu.Unlock()
	return wb.getDoneChanLocked()
}

func (wb *Base) getDoneChanLocked() chan struct{} {
	if wb.doneChan == nil {
		wb.doneChan = make(chan struct{})
	}
	return wb.doneChan
}

// CloseWrapper is used to shut down the worker while waiting for its work to complete.
//
// if closeF is nil, it will be skipped.
func (wb *Base) CloseWrapper(closeF func() error) error {
	// The wait group is used by the close function to ensure that Run has completely released
	// all resources before returning (graceful shutdown). This can take a long time, and
	// the Run methods needs to have access to the done channel while we're waiting. This is
	// why this happens outside of the lock-protected area.
	//
	// Some custom close implementations might want to wait on the waitgroup in the lock-protected
	// area. It is their responsibility to ensure that they do not wait on Run while Run is waiting
	// on them, thus causing a deadlock.
	defer wb.WG.Wait()
	return wb.close(closeF)
}

func (wb *Base) close(closeF func() error) error {
	wb.mu.Lock()
	defer wb.mu.Unlock()
	// Close the done channel while the lock is held. This ensures the channel is also safely
	// initialized only once if it doesn't exist.
	//
	// The channel is closed before the custom close code runs because some custom Run methods
	// might be looking at the done channel to trigger cleanup. Close then runs afterwards to
	// free up any resources that need collecting.
	wb.closeDoneChanLocked()
	if closeF == nil {
		return nil
	}
	return closeF()
}
