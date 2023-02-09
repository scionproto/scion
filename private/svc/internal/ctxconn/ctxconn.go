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

	"github.com/scionproto/scion/pkg/log"
)

type DeadlineCloser interface {
	SetDeadline(t time.Time) error
	io.Closer
}

// CloseConnOnDone closes conn whenever ctx is Done. This includes if ctx is
// canceled via its cancellation function.
//
// Call the returned cancellation function to free up resources and closing the
// connection. The cancellation function returns any error from closing the connection.
func CloseConnOnDone(ctx context.Context, conn DeadlineCloser) func() error {
	if deadline, ok := ctx.Deadline(); ok {
		// ignore error; if deadline cannot be set, we'll just close the conn
		// when the context is Done anyway.
		_ = conn.SetDeadline(deadline)
	}

	ctx, cancelCtx := context.WithCancel(ctx)
	errChan := make(chan error)
	go func() {
		defer log.HandlePanic()
		<-ctx.Done()
		errChan <- conn.Close()
	}()
	return func() error {
		cancelCtx()
		return <-errChan
	}
}
