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
// The main program should call fatal.Init() when it's starting.
//
// Any library producing fatal errors should call fatal.Check() when it starts.
package fatal

import (
	"time"

	"github.com/scionproto/scion/go/lib/log"
)

var (
	fatalC chan struct{}
)

// Initialize the package.
// This MUST be called in the main coroutine when it starts.
func Init() {
	fatalC = make(chan struct{})
}

// Check whether the package was initialized.
// This MUST be called when a library producing fatal errors starts is initialized.
func Check() {
	if fatalC == nil {
		panic("A library producing fatal errors is being used " +
			"but fatal package wasn't initialized.")
	}
}

// Produce a fatal error. This function never exits.
func Fatal(err error) {
	log.Crit("Fatal error", "err", err)
	// Grace period to gather more logs in case that
	// the first fatal error wasn't the most informative one.
	time.Sleep(1 * time.Second)
	// Ask main goroutine to shut down the application.
	select {
	case fatalC <- struct{}{}:
		// Block until the application shuts down.
		select {}
	case <-time.After(5 * time.Second):
		panic("Main goroutine is not responding to the fatal error." +
			"It's probably stuck. Shutting down anyway.")
	}
}

// Get access to the underlying channel. This is used by main goroutine to wait for fatal errors.
func Chan() <-chan struct{} {
	return fatalC
}
