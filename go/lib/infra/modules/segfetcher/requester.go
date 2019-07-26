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

// ReplyOrErr is a seg reply or an error.
type ReplyOrErr struct {
	Reply *path_mgmt.SegReply
	Err   error
}

// Requester requests all segments that can be requested from a request set.
type Requester struct {
	API         RequestAPI
	DstProvider DstProvider
}

// Request the missing segments from the remote. Note that this might only
// fetch a part of the full request set, i.e. if up or down segments are set,
// cores are not yet fetched, assuming the cores are not resolved.
func (r *Requester) Request(ctx context.Context, req RequestSet) <-chan ReplyOrErr {
	switch {
	case req.Up.IsZero() && req.Down.IsZero():
		// only cores to fetch
		return r.fetchReqs(ctx, req.Cores)
	case req.Up.IsZero() && !req.Down.IsZero():
		return r.fetchReqs(ctx, Requests{req.Down})
	case !req.Up.IsZero() && req.Down.IsZero():
		return r.fetchReqs(ctx, Requests{req.Up})
	default:
		return r.fetchReqs(ctx, Requests{req.Up, req.Down})
	}
}

func (r *Requester) fetchReqs(ctx context.Context, reqs Requests) <-chan ReplyOrErr {
	replies := make(chan ReplyOrErr, len(reqs))
	var wg sync.WaitGroup
	for i := range reqs {
		req := reqs[i]
		dst, err := r.DstProvider.Dst(ctx, req)
		if err != nil {
			replies <- ReplyOrErr{Err: err}
			continue
		}
		wg.Add(1)
		go func() {
			defer log.LogPanicAndExit()
			defer wg.Done()

			reply, err := r.API.GetSegs(ctx, &path_mgmt.SegReq{
				RawSrcIA: req.Src.IAInt(),
				RawDstIA: req.Dst.IAInt(),
			}, dst, messenger.NextId())
			replies <- ReplyOrErr{Reply: reply, Err: err}
		}()
	}
	go func() {
		defer log.LogPanicAndExit()
		defer close(replies)
		wg.Wait()
	}()
	return replies
}
