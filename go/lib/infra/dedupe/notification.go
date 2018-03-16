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
	"sync"
	"time"

	cache "github.com/patrickmn/go-cache"
)

const (
	cacheExpirationInterval = time.Minute
)

// notifyList maintains a set of channels for disseminating responses. Each
// channel corresponds to one client call to Deduper.Request.
type notifyList map[ResponseChannel]struct{}

// notificationTable indexes response channels based on broadcast keys and
// dedupe keys. For each local request coming from a client goroutine, a unique
// ResponseChannel is created. The channels are then inserted into the
// notifyLists for the dedupe and broadcast key that describes that request.
type notificationTable struct {
	sync.Mutex

	// broadcast maps broadcast keys to a set of channels that should be
	// notified whenever a request goroutine with that broadcast key completes
	// successfully. Multiple network goroutines might be associated with the
	// same broadcast key.
	broadcast map[string]notifyList

	// dedupe maps dedupe keys to a set of channels that should be notified
	// whenever a network request goroutine with that dedupe key completes with
	// a failure. A single network goroutine is associated with a dedupe key.
	dedupe map[string]notifyList

	// cancelFunctions contains the context cancellation callbacks for all
	// network request goroutines. The map keys are dedupe keys.
	cancelFunctions map[string]CancelFunc

	// cache contains the results of recent successful network requests. If a
	// new request arrives within ResponseValidity time of a successful network
	// request, it does not spawn a new network request and the response
	// is directly taken from this cache. The map is keyed using broadcast keys.
	cache *cache.Cache

	// goroutines contains an inverse map from a channel to the dedupe key it
	// is assigned to. After broadcasts, it is used to clean up (i.e., cancel)
	// goroutines that are running for different dedupe keys but the same
	// broadcast key (as the response has already been written by the
	// broadcast).
	goroutines map[ResponseChannel]string
}

func newNotificationTable() *notificationTable {
	return &notificationTable{
		broadcast:       make(map[string]notifyList),
		dedupe:          make(map[string]notifyList),
		cancelFunctions: make(map[string]CancelFunc),
		// 0 is the default lifetime as we explicitly set lifetimes using set
		cache:      cache.New(0, cacheExpirationInterval),
		goroutines: make(map[ResponseChannel]string),
	}
}

// Add registers ch with the dedupe and broadcast key maps. If a network
// request needs to be issued, the returneed context is non-nil.
func (table *notificationTable) Add(req Request, ch ResponseChannel,
	dedupeLifetime time.Duration) context.Context {

	table.Lock()
	defer table.Unlock()

	bkey := req.BroadcastKey()
	// If the answer is cached and in the grace period, do not bother sending
	// out a request and answer immediately.
	if entryI, expiry, ok := table.cache.GetWithExpiration(bkey); ok {
		response := entryI.(Response)
		// Need to explicitly check expiration date because an entry might be
		// expired but the cache's cleanup goroutine hasn't run yet.
		if expiry.After(time.Now()) {
			ch <- response
			return nil
		} else {
			table.cache.Delete(bkey)
		}
	}

	// We need to chain ch to the notification lists, and start a handler
	// goroutine if one isn't running already.
	var ctx context.Context
	var cancelF context.CancelFunc

	// Insert into dedupe key map. If this is the first channel for the key,
	// initialize a context to signal that the caller should issue a new
	// network request.
	dkey := req.DedupeKey()
	if _, ok := table.dedupe[dkey]; !ok {
		table.dedupe[dkey] = make(notifyList)
		ctx, cancelF = context.WithTimeout(context.Background(), dedupeLifetime)
		table.cancelFunctions[dkey] = CancelFunc(cancelF)
	}
	table.dedupe[dkey][ch] = struct{}{}

	// Insert into broadcast key map. Also, add backlink from channel to dedupe
	// key s.t. we can cancel the network goroutine if the response comes from
	// a broadcast.
	if _, ok := table.broadcast[bkey]; !ok {
		table.broadcast[bkey] = make(notifyList)
	}
	table.broadcast[bkey][ch] = struct{}{}
	table.goroutines[ch] = dkey
	return ctx
}

// Cache saves response in the cache, using the specified key and lifetime d.
func (table *notificationTable) Cache(key string, response Response, d time.Duration) {
	table.cache.Set(key, response, d)
}

// Remove deletes ch from the dedupe and broadcast key maps without writing
// anything on the response channel. This should only be used in the clean-up callbacks
// that are passed back to client goroutines, as only they are aware that the
// response channel is empty and should not be drained. If Remove deletes the
// last channel for a dedupe key, the network goroutine that is associated with
// it is canceled.
func (table *notificationTable) Remove(req Request, ch ResponseChannel) {
	table.Lock()
	defer table.Unlock()
	table.removeLocked(req, ch)
}

// removeLocked is the acquired-lock variant of Remove. It should only be
// called after writing the response to the to-be-removed channel ch.
func (table *notificationTable) removeLocked(req Request, ch ResponseChannel) {
	dedupeKey := req.DedupeKey()
	broadcastKey := req.BroadcastKey()
	delete(table.broadcast[broadcastKey], ch)
	if len(table.broadcast[broadcastKey]) == 0 {
		delete(table.broadcast, broadcastKey)
	}
	delete(table.dedupe[dedupeKey], ch)
	// If there are no more channels on the dedupeKey, it means no client
	// (application) goroutine is waiting for the result of the network request
	// goroutine and we can cancel the latter.
	if len(table.dedupe[dedupeKey]) == 0 {
		delete(table.dedupe, dedupeKey)
		f := table.cancelFunctions[dedupeKey]
		delete(table.cancelFunctions, dedupeKey)
		if f != nil {
			f()
		}
	}
}

// BroadcastError writes response to all the channels waiting on
// req's dedupe key. Response should contain an error and nil data.
func (table *notificationTable) BroadcastError(req Request, response Response) {
	table.Lock()
	defer table.Unlock()

	dkey := req.DedupeKey()
	for ch := range table.dedupe[dkey] {
		select {
		case ch <- response:
			// Now that we have sent the result to the caller, we can remove
			// the references and call the context's cleanup function.
			table.removeLocked(req, ch)
		default:
			// Programming error/race, two writers tried to write to this channel
			panic("unable to write to response channel")
		}
	}
}

// BroadcastSuccess writes response to all the channels waiting on the specified
// broadcast key. Response should contain data and a nil error.
func (table *notificationTable) BroadcastSuccess(key string, response Response) {
	table.Lock()
	defer table.Unlock()

	for ch := range table.broadcast[key] {
		select {
		case ch <- response:
			delete(table.broadcast[key], ch)
			close(ch)

			// Suppose three dedupeKeys were used, AA, AB and AC, and they all
			// have the same broadcast key A. AC returns first with the answer,
			// and every waiting goroutine is notified. We need to delete the
			// notification lists under AA and AB, and cancel the contexts of
			// their requests.
			dedupeKey := table.goroutines[ch]
			delete(table.dedupe, dedupeKey)
			delete(table.goroutines, ch)
			// We just nuked all the notification list for this dedupeKey, so
			// we can call the cancel function immediately.
			f := table.cancelFunctions[dedupeKey]
			delete(table.cancelFunctions, dedupeKey)
			if f != nil {
				f()
			}
		default:
			// Programming error/race, two writers tried to write to this channel
			panic("unable to write to response channel")
		}
	}
}
