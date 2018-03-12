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

package dedupe

import (
	"context"
	"fmt"
	"time"
)

func FooRequestFunc(ctx context.Context, request Request, response chan<- Response) {
	// Just an example, ignore ctx
	exampleRequest := (request).(*ExampleRequest)
	<-time.After(3 * time.Second)
	response <- Response{
		Data:  exampleRequest.ID + 1,
		Error: nil,
	}
}

func Example() {
	// Usage example for the deduplication API. Initialize a mock Deduper, and
	// send two requests. Once the Deduper is implemented, FooRequestFunc will
	// be called just once and both goroutines should be unblocked by the first
	// response coming in.
	dd := &Deduper{
		RequestFunc: RequestFunc(FooRequestFunc),
	}

	go func() {
		<-dd.Request(context.TODO(), &ExampleRequest{ID: 4, Peer: "foo"})
	}()

	<-time.After(time.Second)

	go func() {
		<-dd.Request(context.TODO(), &ExampleRequest{ID: 4, Peer: "bar"})
	}()

	<-time.After(5 * time.Second)
}

type ExampleRequest struct {
	ID   int
	Peer string
}

func (r *ExampleRequest) DedupeKey() string {
	return fmt.Sprintf("%d-%s", r.ID, r.Peer)
}

func (r *ExampleRequest) BroadcastKey() string {
	return fmt.Sprintf("%d", r.ID)
}
