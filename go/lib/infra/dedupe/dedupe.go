// Copyright 2018 ETH Zurich
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

// Package dedupe implements a generic request/response proxy that issues a
// single request instead of multiple redundant requests.
//
// To initialize a Deduper, define the function that handles the request,
// and use it to initialize the Deduper:
//   dd := &Deduper{RequestFunc: foo}
//
// Requests can then be issued:
//   dd.Request(ctx.TODO(), objectA)
//   dd.Request(ctx.TODO(), objectB)
//
// If objectA and objectB have the same DedupeKey() (and arrive at dd at
// approximately the same time, see Deduper timer fields for more information),
// a single call to foo is made.
//
// To support anycast behavior (where multiple requests are sent out to various
// services, and the first response that we get unblocks all waiters), requests
// can define BroadcastKeys.
package dedupe

import (
	"context"
	"sync"
	"time"
)

const (
	DefaultDedupeLifetime = 5 * time.Second
	DefaultGracePeriod    = 1 * time.Second
)

// CancelFunc can be called to cancel a request ahead of time, freeing up
// internal resources (notification lists, goroutines, etc.).
type CancelFunc func()

type Request interface {
	// Two requests are considered identical if they return the same
	// DedupeKey.
	DedupeKey() string
	// When a reply arrives for a request, the reply is delivered to all
	// requests sharing the same broadcast key. If two requests have the same
	// DedupeKey, they must have the same BroadcastKey.  BroadcastKeys allow
	// applications to implement anycast request/responses.  For this, define
	// different DedupeKey for the same message sent to different remote
	// servers, while keeping the BroadcastKey the same.
	BroadcastKey() string
}

// RequestFunc performs a request/response exchange, with the response written
// on the channel. To support proper clean-up, RequestFunc must write exactly
// one value to response. The Response is transparently passed by the
// Deduper to all callers waiting on the same BroadcastKey. To avoid leaks,
// RequestFunc must take ctx into account and correctly time out/terminate if
// the context is Done.
//
// When sending out a fresh request, the Deduper calls RequestFunc in a
// goroutine, and selects on ctx.Done() and on the response channel.
//
// Use TestRequestFunc to verify that an implementation is valid
// for use with Deduper.
type RequestFunc func(ctx context.Context, request Request) Response

// A Deduper issues a single request instead of multiple identical
// requests. Responses get broadcast to all waiters. For more information, see
// the package level documentation.
//
// The zero value is a valid Deduper object. Members variables should only be
// set during initialization; setting them after the first Request is undefined
// behavior.
type Deduper struct {
	// Function to call when a new request needs to be sent out.
	RequestFunc RequestFunc

	// DedupeLifetime is the timeout for network requests. For DedupeLifetime
	// time after a fresh network request is sent out (for a DedupeKey), no new
	// network requests are sent out. Once the request completes, all callers
	// of Request are notified.  If unset, DedupeLifetime defaults to
	// DefaultDedupeLifetime.
	DedupeLifetime time.Duration

	// Time after a successful network request where no new network requests
	// for the same broadcast key are sent out. The result is immediately
	// returned from an internal cache for this period.
	GracePeriod time.Duration

	// Mutex for notification table initialization
	mu sync.Mutex
	// Internal table for notification lists and caches.
	notifications *notificationTable
}

type ResponseChannel chan Response

// Request passes a request that is subject to deduplication. This function
// returns immediately, and callers should wait on the returned channel for the
// result. The second return value is a cancellation function that can be used
// to free up resources associated with the request. It is safe to call Request
// from multiple goroutines.
//
// Objects written to the channel might share the same address space, so
// callers should copy the value drained from the channel if they want to have
// exclusive ownership.
func (dd *Deduper) Request(ctx context.Context, req Request) (<-chan Response, CancelFunc) {
	dd.mu.Lock()
	if dd.notifications == nil {
		dd.notifications = newNotificationTable()
	}
	dd.mu.Unlock()

	ch := make(chan Response, 1)
	if ctx := dd.notifications.Add(req, ch, dd.dedupeLifetime()); ctx != nil {
		go dd.handler(ctx, req)
	}

	return ch, func() {
		// Give callers the option of cleaning up resources prior to the
		// Request returning.
		dd.notifications.Remove(req, ch)
	}
}

// handler calls RequestFunc with a freshly created channel, and then reads the
// result from the channel and notifies the relevant waiters.
func (dd *Deduper) handler(ctx context.Context, req Request) {
	ch := make(chan Response, 1)
	go func() {
		ch <- dd.RequestFunc(ctx, req)
	}()

	// There are two possible ways RequestFunc finishes. During normal
	// operation, ctx.Done returns nil and ch is populated with a retrieved
	// object. During errors, both the context is marked as Done (via external
	// cancellation or expiry) and ch contains an error. Because the top-level
	// cases in the select below are nondeterministic, we also propagate context
	// expiration errors on the second branch.
	select {
	case <-ctx.Done():
		response := Response{Data: nil, Error: ctx.Err()}
		dd.notifications.BroadcastError(req, response)
	case response := <-ch:
		if response.Error != nil {
			// Make sure Data is nil on errors
			response := Response{Data: nil, Error: response.Error}
			dd.notifications.BroadcastError(req, response)
		} else {
			dd.notifications.BroadcastSuccess(req.BroadcastKey(), response)
			dd.notifications.Cache(req.BroadcastKey(), response, dd.GracePeriod)
		}
	}
}

func (dd *Deduper) dedupeLifetime() time.Duration {
	if dd.DedupeLifetime == 0 {
		return DefaultDedupeLifetime
	}
	return dd.DedupeLifetime
}

func (dd *Deduper) gracePeriod() time.Duration {
	if dd.GracePeriod == 0 {
		return DefaultGracePeriod
	}
	return dd.GracePeriod
}

// Response represents the outcome of a request. It is passed along channels by
// the Deduper.
type Response struct {
	Data  interface{}
	Error error
}
