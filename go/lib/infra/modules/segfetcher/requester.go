// Copyright 2019 Anapaya Systems
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

package segfetcher

import (
	"context"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
)

// RequestAPI is the API to get segments from the network.
type RequestAPI interface {
	GetSegs(ctx context.Context, msg *path_mgmt.SegReq, a net.Addr,
		id uint64) (*path_mgmt.SegReply, error)
}

// DstProvider provides the destination for a segment lookup.
type DstProvider interface {
	Dst(context.Context, Request) (net.Addr, error)
}

// ReplyOrErr is a seg reply or an error for the given request.
type ReplyOrErr struct {
	Req   Request
	Reply *path_mgmt.SegReply
	Peer  net.Addr
	Err   error
}

// Requester requests segments.
type Requester interface {
	Request(ctx context.Context, req RequestSet) <-chan ReplyOrErr
}

// DefaultRequester requests all segments that can be requested from a request set.
type DefaultRequester struct {
	API         RequestAPI
	DstProvider DstProvider
}

// Request all requests in the request set that are in fetch state.
func (r *DefaultRequester) Request(ctx context.Context, req RequestSet) <-chan ReplyOrErr {
	var reqs Requests
	allReqs := append(Requests{req.Up, req.Down}, req.Cores...)
	for _, req := range allReqs {
		if req.State == Fetch {
			reqs = append(reqs, req)
		}
	}
	return r.fetchReqs(ctx, reqs)
}

func (r *DefaultRequester) fetchReqs(ctx context.Context, reqs Requests) <-chan ReplyOrErr {
	replies := make(chan ReplyOrErr, len(reqs))
	var wg sync.WaitGroup
	for i := range reqs {
		req := reqs[i]
		dst, err := r.DstProvider.Dst(ctx, req)
		if err != nil {
			replies <- ReplyOrErr{Req: req, Err: err}
			continue
		}
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			reply, err := r.API.GetSegs(ctx, req.ToSegReq(), dst, messenger.NextId())
			replies <- ReplyOrErr{Req: req, Reply: reply, Peer: dst, Err: err}
		}()
	}
	go func() {
		defer log.HandlePanic()
		defer close(replies)
		wg.Wait()
	}()
	return replies
}
