// Copyright 2019 ETH Zurich
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

// Package ctxconn provides a helper function to track context cancellation when
// working with connections.
package ctxconn

import (
	"context"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/log"
)

type DeadlineCloser interface {
	SetDeadline(t time.Time) error
	io.Closer
}

// CancelFunc can be used to shut down context watchers. It is safe to call the
// cancel function multiple times.
type CancelFunc func()

// CloseConnOnDone closes conn whenever ctx is Done. This includes if ctx is
// canceled via its cancellation function.
//
// Call the returned cancellation function to free up resources. Calling this
// function does not guarantee that the connection has been closed. It is not
// safe to call the returned function multiple times at the same time.
func CloseConnOnDone(ctx context.Context, conn DeadlineCloser) CancelFunc {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	cancelSignal := make(chan struct{})
	go func() {
		defer log.LogPanicAndExit()
		select {
		case <-ctx.Done():
			// It's safe to call close multiple times
			if err := conn.Close(); err != nil {
				log.Warn("Error closing conn when ctx canceled", "err", err)
			}
		case <-cancelSignal:
			// shut down goroutine, free up resources
			return
		}
	}()
	return func() {
		select {
		case <-cancelSignal:
		default:
			close(cancelSignal)
		}
	}
}
