// Copyright 2018 ETH Zurich, Anapaya Systems
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

// FIXME(scrye): These tests are somewhat vulnerable to race conditions
// (although the delays are quite generous). If they become an issue in CI, we
// should consider adjusting timers or adding a "flaky" build flag to the file.
// Sadly, due to the asynchronous nature of Deduper, having tests that aren't
// flaky is quite challenging.

package dedupe

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

// TRequest describes a test request and implements interface Request; test
// cases include a sequence of TRequests.
type TRequest struct {
	DKey string
	BKey string
	// Data and Error are the cooked request response (simulates network response)
	Data  string
	Error error

	// Delay is the time (in milliseconds) to wait before the Request runs in
	// the test.
	Delay int
	// Latency is how long it takes (in milliseconds) for Request to complete.
	Latency int
}

func (request *TRequest) DedupeKey() string {
	return request.DKey
}

func (request *TRequest) BroadcastKey() string {
	return request.BKey
}

// remoteServer tracks the number of Request functions that fire (that would
// actually result in traffic on the network).
type remoteServer struct {
	mu              sync.Mutex
	handledRequests map[string]uint
}

// Handler is a RequestFunc for the Deduper that also tracks the number of
// network requests via srv's state.
func (srv *remoteServer) Handler(ctx context.Context, request Request) Response {
	trequest := request.(*TRequest)
	srv.mu.Lock()
	srv.handledRequests[request.DedupeKey()]++
	srv.mu.Unlock()
	select {
	case <-time.After(time.Duration(trequest.Latency) * time.Millisecond):
		// Normal
		return Response{
			Data:  trequest.Data,
			Error: trequest.Error,
		}
	case <-ctx.Done():
		// Context canceled, probably during clean-up
		return Response{
			Data:  nil,
			Error: ctx.Err(),
		}
	}
}

func TestDeduper(t *testing.T) {
	testCases := []struct {
		Name        string
		requests    []TRequest
		results     []Response
		serverState map[string]uint
	}{
		{
			Name: "one request",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 0},
			},
			results: []Response{
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a-x": 1},
		},
		{
			Name: "one request with error",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "", Error: fmt.Errorf("bad"), Latency: 0},
			},
			results: []Response{
				{Data: nil, Error: fmt.Errorf("bad")},
			},
			serverState: map[string]uint{"a-x": 1},
		},
		{
			Name: "one request with bkey = dkey",
			requests: []TRequest{
				{DKey: "a", BKey: "a", Data: "foo", Error: nil, Latency: 0},
			},
			results: []Response{
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a": 1},
		},
		{
			Name: "two requests, same dedupe key, same broadcast key",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 250},
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 250},
			},
			results: []Response{
				{Data: "foo", Error: nil},
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a-x": 1},
		},
		{
			Name: "two requests, different dedupe key, same broadcast keys",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 250},
				{DKey: "a-y", BKey: "a", Data: "foo", Error: nil, Latency: 250},
			},
			results: []Response{
				{Data: "foo", Error: nil},
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a-x": 1, "a-y": 1},
		},
		{
			Name: "multiple requests with same broadcast key, data comes from first",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "toolate", Error: nil, Latency: 400},
				{DKey: "a-y", BKey: "a", Data: "toolate", Error: nil, Latency: 400},
				{DKey: "a-z", BKey: "a", Data: "foo", Error: nil, Latency: 250},
			},
			results: []Response{
				{Data: "foo", Error: nil},
				{Data: "foo", Error: nil},
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a-x": 1, "a-y": 1, "a-z": 1},
		},
		{
			Name: "fired request times out, announces error",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 3000},
			},
			results: []Response{
				{Data: nil, Error: context.DeadlineExceeded},
			},
			serverState: map[string]uint{"a-x": 1},
		},
		{
			Name: "request, and then request in grace period",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 0},
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Delay: 500, Latency: 0},
				{DKey: "a-y", BKey: "a", Data: "foo", Error: nil, Delay: 0, Latency: 0},
			},
			results: []Response{
				{Data: "foo", Error: nil},
				{Data: "foo", Error: nil},
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a-x": 1},
		},
		{
			Name: "request, and then request outside grace period",
			requests: []TRequest{
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 0},
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Delay: 1500, Latency: 0},
			},
			results: []Response{
				{Data: "foo", Error: nil},
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a-x": 2},
		},
		{
			Name: "network request returns with error, inform dedupe key instead of broadcast key",
			requests: []TRequest{
				// T=0, start a-x; T=400, start a-y;
				// T=500, cancel a-x (deadline); T=650, a-y completes;
				{DKey: "a-x", BKey: "a", Data: "foo", Error: nil, Latency: 750},
				{DKey: "a-y", BKey: "a", Data: "foo", Error: nil, Delay: 400, Latency: 250},
			},
			results: []Response{
				{Data: nil, Error: context.DeadlineExceeded},
				{Data: "foo", Error: nil},
			},
			serverState: map[string]uint{"a-x": 1, "a-y": 1},
		},
	}

	Convey("initialize deduper", t, func() {
		// Initialize a fresh deduper for each goconvey test path
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				// 500ms max allowed request time, 1000ms grace period
				deduper, server := Init(500*time.Millisecond, 1000*time.Millisecond)
				chs := make(map[int]<-chan Response)
				for i := range tc.requests {
					<-time.After(time.Duration(tc.requests[i].Delay) * time.Millisecond)
					ch, cancelF := deduper.Request(context.TODO(), &tc.requests[i])
					chs[i] = ch
					defer cancelF()
				}
				for i := range tc.results {
					SoMsg(strconv.Itoa(i), <-chs[i], ShouldResemble, tc.results[i])
				}
				// reading the map doesn't race (bar programming errors)
				// because by draining the channels we confirmed that all
				// running goroutines ended.
				SoMsg("requests fired", server.handledRequests, ShouldResemble, tc.serverState)
			})
		}
	})
}

func Init(dedupeLifetime time.Duration, gracePeriod time.Duration) (Deduper, *remoteServer) {
	server := &remoteServer{
		handledRequests: make(map[string]uint),
	}
	deduper := New(
		server.Handler,
		dedupeLifetime,
		gracePeriod,
	)
	return deduper, server
}
