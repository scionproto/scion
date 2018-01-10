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
	replyMap replyChannelMap

	lock        sync.Mutex
	destroyChan chan struct{}
}

func newWaitTable(keyF func(Message) string) *waitTable {
	return &waitTable{
		keyF:        keyF,
		destroyChan: make(chan struct{}),
	}
}

func (wt *waitTable) addRequest(object Message) error {
	select {
	case <-wt.destroyChan:
		return common.NewBasicError("Table destroyed", nil)
	default:
	}
	replyChannel := make(chan Message, 1)
	_, loaded := wt.replyMap.LoadOrStore(wt.keyF(object), replyChannel)
	if loaded {
		return common.NewBasicError("Duplicate key", nil, "key", wt.keyF(object))
	}

	return nil
}

func (wt *waitTable) cancelRequest(object Message) {
	wt.replyMap.Delete(wt.keyF(object))
}

func (wt *waitTable) waitForReply(ctx context.Context, object Message) (Message, error) {
	select {
	case <-wt.destroyChan:
		return nil, common.NewBasicError("Table destroyed", nil)
	default:
	}
	replyChannel, loaded := wt.replyMap.Load(wt.keyF(object))
	if !loaded {
		return nil, common.NewBasicError("Key not found", nil, "key", wt.keyF(object))
	}
	select {
	case reply := <-replyChannel:
		return reply, nil
	case <-ctx.Done():
		return nil, infra.NewCtxDoneError()
	case <-wt.destroyChan:
		return nil, common.NewBasicError("Table destroyed", nil)
	}
}

// reply sends object to the waiting goroutine. If a waiting goroutine is
// found, the returned bool value is true. If no waiting goroutine is found,
// the returned bool value is false and error is nil.
func (wt *waitTable) reply(object Message) (bool, error) {
	select {
	case <-wt.destroyChan:
		return false, common.NewBasicError("Table destroyed", nil)
	default:
	}
	replyChannel, ok := wt.replyMap.Load(wt.keyF(object))
	if !ok {
		return false, nil
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
		return false, common.NewBasicError("Duplicate reply key", nil, "key", wt.keyF(object))
	}
	return true, nil
}

func (wt *waitTable) Destroy() {
	wt.lock.Lock()
	defer wt.lock.Unlock()
	select {
	case <-wt.destroyChan:
		// Channel already closed by some other goroutine
	default:
		close(wt.destroyChan)
	}
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
