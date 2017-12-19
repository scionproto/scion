// Copyright 2017 ETH Zurich
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

package disp

import (
	"context"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
)

type waitTable struct {
	keyF     func(Message) string
	t        replyChannelMap
	destroyC chan struct{}
}

func newWaitTable(keyF func(Message) string) *waitTable {
	return &waitTable{
		keyF:     keyF,
		destroyC: make(chan struct{}),
	}
}

func (wt *waitTable) AddRequest(object Message) error {
	select {
	case <-wt.destroyC:
		return common.NewCError("Table destroyed")
	default:
		// Continue below
	}
	// Destroy can be called between now and when we exit this function.

	replyChannel := make(chan Message, 1)
	_, loaded := wt.t.LoadOrStore(wt.keyF(object), replyChannel)
	if loaded {
		return common.NewCError("Duplicate key", "key", wt.keyF(object))
	}

	return nil
}

func (wt *waitTable) CancelRequest(object Message) {
	wt.t.Delete(wt.keyF(object))
}

func (wt *waitTable) WaitForReply(ctx context.Context, object Message) (Message, error) {
	select {
	case <-wt.destroyC:
		return nil, common.NewCError("Table destroyed")
	default:
		// Continue below
	}
	// Destroy can be called between now and when we exit this function.

	replyChannel, loaded := wt.t.Load(wt.keyF(object))
	if !loaded {
		return nil, common.NewCError("Key not found", "key", wt.keyF(object))
	}

	select {
	case reply := <-replyChannel:
		return reply, nil
	case <-ctx.Done():
		return nil, infra.NewCtxDoneError()
	case <-wt.destroyC:
		return nil, common.NewCError("Table destroyed")
	}
}

func (wt *waitTable) Reply(object Message) error {
	select {
	case <-wt.destroyC:
		return common.NewCError("Table destroyed")
	default:
		// Continue below
	}
	// Destroy can be called between now and when we exit this function.

	replyChannel, loaded := wt.t.Load(wt.keyF(object))
	if !loaded {
		return common.NewCError("Reply received, but no one is waiting", "key", wt.keyF(object))
	}

	select {
	case replyChannel <- object:
		// NOTE(scrye): Do not close the channel to prevent future writers from
		// panicking if a duplicate reply arrives. Note that if the waiting
		// goroutine drains the channel before a duplicate reply arrives, the
		// duplicate will match this case again. This does not leak a channel,
		// because the reader deletes the reference from the map and it gets
		// GC'd. However, the duplicate will not be logged.
	default:
		// Duplicate reply and the channel is already full. While this is not
		// an error, it is useful to log.
		return common.NewCError("Duplicate reply key", "key", wt.keyF(object))
	}
	return nil
}

func (wt *waitTable) Destroy() {
	close(wt.destroyC)
}

type replyChannelMap sync.Map

func (m *replyChannelMap) Delete(key string) {
	(*sync.Map)(m).Delete(key)
}

func (m *replyChannelMap) Load(key string) (chan Message, bool) {
	value, loaded := (*sync.Map)(m).Load(key)
	if value == nil {
		return nil, loaded
	}
	return value.(chan Message), loaded
}

func (m *replyChannelMap) LoadOrStore(key string, value chan Message) (chan Message, bool) {
	newValue, loaded := (*sync.Map)(m).LoadOrStore(key, value)
	if newValue == nil {
		return nil, loaded
	}
	return newValue.(chan Message), loaded
}

func (m *replyChannelMap) Range(f func(string, chan Message) bool) {
	(*sync.Map)(m).Range(func(k, v interface{}) bool {
		return f(k.(string), v.(chan Message))
	})
}

func (m *replyChannelMap) Store(key string, value chan Message) {
	(*sync.Map)(m).Store(key, value)
}
