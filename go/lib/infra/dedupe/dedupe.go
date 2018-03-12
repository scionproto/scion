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
// If objectA and objectB have the sam DedupeKey() (and arrive at dd at
// approximately the same time, see Deduper timer fields for more information),
// a single call to foo is made.
//
// To support anycast behavior (where multiple requests are sent out to various
// services, and the first response that we get unblocks all waiters), requests
// can define BroadcastKeys.
package dedupe

import (
	"context"
	"time"
)

const (
	DefaultDedupeLifetime = time.Minute
)

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
// Deduper to all callers waiting on the same BroadcastKey.
//
// When sending out a fresh request, the Deduper calls RequestFunc in a
// goroutine, and selects on ctx.Done() and on the response channel.
//
// Use TestRequestFunc to verify that an implementation is valid
// for use with Deduper.
type RequestFunc func(ctx context.Context, request Request, response chan<- Response)

// A Deduper issues a single request instead of multiple identical
// requests. Responses get broadcast to all waiters. For more information, see
// the package level documentation.
//
// The zero value is a valid Deduper object.
type Deduper struct {
	// Function to call when a new request needs to be sent out.
	RequestFunc RequestFunc

	// Time after calling RequestFunc for a specific DedupeKey where all
	// requests for the same key will not result in an additional call to
	// RequestFunc. If unset, DedupeLifetime defaults to DefaultDedupeLifetime.
	DedupeLifetime time.Duration

	// XXX(scrye): Add more fields here to support the customization
	// of Deduper behavior and timing.
}

// Request passes a request that is subject to deduplication. This function
// returns immediately, and callers should wait on the returned channel for the
// result.
func (dd *Deduper) Request(ctx context.Context, object Request) <-chan Response {
	// TODO(scrye): No aggregation logic yet, so just call the handler
	ch := make(chan Response, 1)
	dd.RequestFunc(ctx, object, ch)
	// TODO(scrye): Replicate content of ch across all broadcast channels
	return ch
}

// Response represents the outcome of a request. It is passed along channels by
// the Deduper.
type Response struct {
	Data  interface{}
	Error error
}

// TestRequestFunc checks whether f is a correct RequestFunc implementation, as
// expected by Deduper objects. It is designed for use in tests.
func TestRequestFunc(f RequestFunc) error {
	panic("not implemented")
}
