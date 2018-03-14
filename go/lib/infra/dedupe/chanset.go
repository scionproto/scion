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
)

// notifyList maintains a set of channels for disseminating responses. The keys
// map to themselves. Each channel corresponds to one client call to
// Deduper.Request.
type notifyList map[ResponseChannel]ResponseChannel

// cacheEntry describes a value obtained via a successful network request.
//
// FIXME(scrye): Currently cacheEntries leak memory; they expire, but are not
// cleaned up from the cache if they are not accessed after they have expired.
// A periodic cacheEntry clean-up function should be included.
type cacheEntry struct {
	object    Response
	timestamp time.Time
}

// notificationTable indexes response channels based on broadcast keys and
// dedupe keys. For each local request coming from a client goroutine, a unique
// ResponseChannel is created. The channels are then inserted into the
// notifyLists for the dedupe and broadcast key that describes that request.
type notificationTable struct {
	sync.Mutex

	GracePeriod time.Duration

	DedupeLifetime time.Duration

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
	// new request arrives within GracePeriod time of a successful network
	// request, it does not spawn a new network request and the response
	// is directly taken from this cache. The map is keyed using broadcast keys.
	cache map[string]*cacheEntry

	// goroutines contains an inverse map from a channel to the dedupe key it
	// is assigned to. After broadcasts, it is used to clean up (i.e., cancel)
	// goroutines that are running for different dedupe keys but the same
	// broadcast key (as the response has already been written by the
	// broadcast).
	goroutines map[ResponseChannel]string
}

// Add registers ch with the dedupe and broadcast key maps. If a network
// request needs to be issued, the returneed context is non-nil.
func (table *notificationTable) Add(object Request, ch ResponseChannel) context.Context {
	table.Lock()
	defer table.Unlock()

	// If the answer is cached and in the grace period, do not bother sending
	// out a request and answer immediately.
	if entry, ok := table.cache[object.BroadcastKey()]; ok {
		if entry.timestamp.Add(table.GracePeriod).After(time.Now()) {
			ch <- entry.object
			return nil
		} else {
			delete(table.cache, object.BroadcastKey())
		}
	}

	// We need to chain ch to the notification lists, and start a handler
	// goroutine if one isn't running already.
	var ctx context.Context
	var cancelF context.CancelFunc

	// Insert into dedupe key map. If this is the first channel for the key,
	// initialize a context to signal that the caller should issue a new
	// network request.
	dkey := object.DedupeKey()
	if _, ok := table.dedupe[dkey]; !ok {
		table.dedupe[dkey] = make(notifyList)
		ctx, cancelF = context.WithTimeout(context.Background(), table.DedupeLifetime)
		table.cancelFunctions[dkey] = CancelFunc(cancelF)
	}
	table.dedupe[dkey][ch] = ch

	// Insert into broadcast key map. Also, add backlink from channel to dedupe
	// key s.t. we can cancel the network goroutine if the response comes from
	// a broadcast.
	bkey := object.BroadcastKey()
	if _, ok := table.broadcast[bkey]; !ok {
		table.broadcast[bkey] = make(notifyList)
	}
	table.broadcast[bkey][ch] = ch
	table.goroutines[ch] = dkey
	return ctx
}

// Cache saves object in the cache, using the specified key. The current time
// is used to time-stamp the entry.
func (table *notificationTable) Cache(key string, object Response) {
	table.Lock()
	defer table.Unlock()
	table.cache[key] = &cacheEntry{
		timestamp: time.Now(),
		object:    object,
	}
}

// Remove deletes ch from the dedupe and broadcast key maps without writing
// anything on the response channel. This should only be used in the clean-up callbacks
// that are passed back to client goroutines, as only they are aware that the
// response channel is empty and should not be drained. If Remove deletes the
// last channel for a dedupe key, the network goroutine that is associated with
// it is canceled.
func (table *notificationTable) Remove(object Request, ch ResponseChannel) {
	table.Lock()
	defer table.Unlock()
	table.removeLocked(object, ch)
}

// removeLocked is the acquired-lock variant of Remove. It should only be
// called after writing the response to the to-be removed channel ch.
func (table *notificationTable) removeLocked(object Request, ch ResponseChannel) {
	dedupeKey := object.DedupeKey()
	broadcastKey := object.BroadcastKey()
	delete(table.broadcast[broadcastKey], ch)
	delete(table.dedupe[dedupeKey], ch)
	// If there are no more channels on the dedupeKey, it means no goroutine is
	// still waiting for the request and we can cancel it.
	if len(table.dedupe[dedupeKey]) == 0 {
		f := table.cancelFunctions[dedupeKey]
		delete(table.cancelFunctions, dedupeKey)
		if f != nil {
			f()
		}
	}
}

// BroadcastError writes response to all the channels waiting on
// object's dedupe key. Response should contain an error and nil data.
func (table *notificationTable) BroadcastError(object Request, response Response) {
	table.Lock()
	defer table.Unlock()

	dkey := object.DedupeKey()
	for ch := range table.dedupe[dkey] {
		select {
		case ch <- response:
			// Now that we have sent the result to the caller, we can remove
			// the references and call the context's cleanup function.
			table.removeLocked(object, ch)
		default:
			// Programming error/race, two writers tried to write to this channel
			panic("unable to write to response channel")
		}
	}
}

// BroadcastSuccess writes response to all the channels waiting on object's
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
