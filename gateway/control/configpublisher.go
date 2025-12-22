// Copyright 2020 Anapaya Systems
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

package control

import (
	"sync"

	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
)

// ConfigPublisher can be used to send configs to multiple clients via different
// means (channels, getters).
type ConfigPublisher struct {
	mtx sync.RWMutex
	// sessionPolicies holds the session policies that were loaded last.
	sessionPolicies SessionPolicies
	// routingPolicy holds the routing policy that was loaded last.
	routingPolicy *routing.Policy

	sessionPoliciesSubscribers []chan SessionPolicies
	routingPoliciesSubscribers []chan *routing.Policy
	remoteIAsSubscribers       []chan []addr.IA
}

// Publish notifies clients of the Publisher about new configurations. Nil
// values are allowed and mean the nil config is not published, this is to
// allow updates of only one config.
func (n *ConfigPublisher) Publish(sp SessionPolicies, rp *routing.Policy) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	var wg sync.WaitGroup
	if sp != nil {
		n.sessionPolicies = sp.Copy()
		for _, c := range n.sessionPoliciesSubscribers {
			wg.Go(func() {
				defer log.HandlePanic()
				c <- sp.Copy()
			})
		}
		for _, c := range n.remoteIAsSubscribers {
			wg.Go(func() {
				defer log.HandlePanic()
				c <- sp.RemoteIAs()
			})
		}
	}
	if rp != nil {
		n.routingPolicy = rp.Copy()
		for _, c := range n.routingPoliciesSubscribers {
			wg.Go(func() {
				defer log.HandlePanic()
				c <- rp.Copy()
			})
		}
	}
	wg.Wait()
}

// SubscribeSessionPolicies returns a channel on which new session policies will
// be sent. The channel has capacity 0. If a reader is slow to process the
// subscription, it will prevent the Publisher from publishing new
// configurations.
//
// Subscriptions happening prior to a Publish are guaranteed to return the new
// state read by the NotPublishify.
func (n *ConfigPublisher) SubscribeSessionPolicies() <-chan SessionPolicies {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	c := make(chan SessionPolicies)
	n.sessionPoliciesSubscribers = append(n.sessionPoliciesSubscribers, c)
	return c
}

func (n *ConfigPublisher) SubscribeRoutingPolicies() <-chan *routing.Policy {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	c := make(chan *routing.Policy)
	n.routingPoliciesSubscribers = append(n.routingPoliciesSubscribers, c)
	return c
}

// SubscribeRemoteIAs returns a channel on which remote IAs will
// be sent. The channel has capacity 0. If a reader is slow to process the
// subscription, it will prevent the Publisher from publishing new
// configurations.
//
// Subscriptions happening prior to a Publish are guaranteed to return the new
// state read by the NotPublishify.
func (n *ConfigPublisher) SubscribeRemoteIAs() <-chan []addr.IA {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	c := make(chan []addr.IA)
	n.remoteIAsSubscribers = append(n.remoteIAsSubscribers, c)
	return c
}

// RoutingPolicy returns the last routing policy that was published.
// The returned object is a deep-copy, and can be edited by the caller.
func (n *ConfigPublisher) RoutingPolicy() *routing.Policy {
	n.mtx.RLock()
	defer n.mtx.RUnlock()

	if n.routingPolicy == nil {
		return nil
	}
	return n.routingPolicy.Copy()
}
