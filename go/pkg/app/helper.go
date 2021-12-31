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

package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ASInfo holds information about the local AS.
type ASInfo struct {
	IA  addr.IA
	MTU uint16
}

// QueryASInfo queries information about the local AS from the SCION Daemon.
func QueryASInfo(ctx context.Context, conn daemon.Connector) (ASInfo, error) {
	asInfo, err := conn.ASInfo(ctx, 0)
	if err != nil {
		return ASInfo{}, err
	}
	return ASInfo{
		IA:  asInfo.IA,
		MTU: asInfo.MTU,
	}, nil
}

// WithSignal derives a child context that subsribes a signal handler for the
// provided signals. The returned context gets cancled if any of the subscribed
// signals is received
func WithSignal(ctx context.Context, sig ...os.Signal) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	stop := make(chan os.Signal, len(sig))
	signal.Notify(stop, sig...)

	go func() {
		defer log.HandlePanic()
		defer signal.Stop(stop)
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx
}

// SIGHUPChannel returns a channel that is triggered whenever a SIGHUP signal is
// sent to the process. The context is used for clean up, it deregisters the
// SIGHUP channel and terminates the backgroun go routine on cancellation.
func SIGHUPChannel(ctx context.Context) chan struct{} {
	sighupC := make(chan os.Signal, 1)
	signal.Notify(sighupC, syscall.SIGHUP)
	ch := make(chan struct{})
	go func() {
		defer log.HandlePanic()
		defer signal.Stop(sighupC)
		for {
			select {
			case <-sighupC:
				ch <- struct{}{}
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}

// Cleanup defines a list of cleanup hooks. This can be helpful when creating an
// app and then adding multiple cleanup hooks and to make sure that the all
// execute without error.
type Cleanup []func() error

// Add adds a cleanup hook that will be executed when Do is called.
func (c *Cleanup) Add(f func() error) {
	*c = append(*c, f)
}

// Do executes all the cleanup functions.
func (c *Cleanup) Do() error {
	var errs serrors.List
	for _, f := range *c {
		if err := f(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs.ToError()
}
