// Copyright 2018 Anapaya Systems
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

// Package fatal provides a way to handle fatal errors.
// 1. It gives the main goroutine an opportunity to cleanly shut down in case of a fatal error.
// 2. If main goroutine is non-responsive it terminates the process.
// 3. To improve debugging, after the first fatal error the other goroutines
//    are given a grace period so that we have more logs to investigate.
//
// Also implemented is a clean shutdown option, for non-error events that
// trigger clean application shutdown (e.g., a signal received from the user).
//
// The main program should call fatal.Init() when it's starting.
//
// Any library producing fatal errors should call fatal.Check() when it starts.
package fatal

import (
	"fmt"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/log"
)

const (
	// FatalDelayInterval is the interval between when a package signals that a
	// fatal event has occurred, and when drainers of the fatal channel are
	// informed. This allows for collecting more informative logs before
	// tearing the application down.
	FatalDelayInterval = time.Second
	// FatalGraceInterval is the time in which the main goroutine should shut
	// the application down.
	FatalGraceInterval = 5 * time.Second
)

var (
	initialized bool

	fatalMtx    sync.Mutex
	fatalClosed bool
	// fatalC is used for signals asking for forceful termination of the application.
	fatalC chan struct{}

	shutdownMtx    sync.Mutex
	shutdownClosed bool
	// shutdownC is used for signals asking for clean shutdown of the application.
	shutdownC chan struct{}
)

// Init Initializes the package.
// This MUST be called in the main goroutine when it starts.
func Init() {
	fatalC = make(chan struct{})
	shutdownC = make(chan struct{})
	initialized = true
}

// Check checks whether the package was initialized.
// This MUST be called when a library producing fatal errors starts is initialized.
func Check() {
	if !initialized {
		panic("A library producing fatal errors is being used " +
			"but fatal package wasn't initialized.")
	}
}

// Fatal produces a fatal error. This function never exits.
func Fatal(err error) {
	log.Error("Fatal error", "err", err)
	// Grace period to gather more logs in case that
	// the first fatal error wasn't the most informative one.
	time.Sleep(FatalDelayInterval)

	// Ask main goroutine to shut down the application.
	fatalMtx.Lock()
	if !fatalClosed {
		close(fatalC)
		fatalClosed = true

		// If the main goroutine fatals out correctly, this won't get a chance
		// to run.
		time.AfterFunc(FatalGraceInterval, func() {
			defer log.HandlePanic()
			panic("Main goroutine is not responding to the fatal error. " +
				"It's probably stuck. Shutting down anyway.")
		})
	}
	fatalMtx.Unlock()

	select {}
}

// Shutdown closes the shutdown channel, thus informing channel
// drainers (usually the main goroutine) that the application should be cleanly
// shut down. If the application does not shut down in the specified duration,
// it is forcefully torn down.
//
// Shutdown blocks forever.
func Shutdown(d time.Duration) {
	log.Info("Shutdown called, waiting a limited amount of time until forceful shutdown",
		"time_allowance", d)
	// Inform drainer if not informed already
	shutdownMtx.Lock()
	if !shutdownClosed {
		close(shutdownC)
		shutdownClosed = true

		// If the main goroutine shuts down everything in time, this won't get
		// a chance to run.
		time.AfterFunc(d, func() {
			defer log.HandlePanic()
			panic(fmt.Sprintf("Main goroutine did not shut down in time (waited %v). It's "+
				"probably stuck. Forcing shutdown.", d))
		})
	}
	shutdownMtx.Unlock()

	select {}
}

// FatalChan returns a read-only channel that is closed when a fatal condition
// has occurred.
func FatalChan() <-chan struct{} {
	return fatalC
}

// ShutdownChan returns a read-only channel that is closed when the application
// should be cleanly shut down.
func ShutdownChan() <-chan struct{} {
	return shutdownC
}
