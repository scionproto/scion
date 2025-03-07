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

// Package pathhealth monitors paths to different ASes. Call Monitor.Register()
// to start monitoring paths to a remote AS using a chosen path policy. The call
// returns a registration object which can be used to obtain the best path.
package pathhealth

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// defaultPathUpdateInterval specifies how often the paths are retrieved from the daemon.
	defaultPathUpdateInterval = 10 * time.Second
)

type RemoteWatcher interface {
	Run(context.Context)
	PathWatchers() []PathWatcher
}

// RemoteWatcherFactory creates RemoteWatchers.
type RemoteWatcherFactory interface {
	New(remote addr.IA) RemoteWatcher
}

// RevocationStore keeps track of revocations.
type RevocationStore interface {
	// AddRevocation adds a revocation.
	AddRevocation(ctx context.Context, rev *path_mgmt.RevInfo)
	// IsRevoked returns true if there is at least one revoked interface on the path.
	IsRevoked(path snet.Path) bool
	// Cleanup removes all expired revocations.
	Cleanup(ctx context.Context)
}

type Monitor struct {
	// RemoteWatcherFactory creates a RemoteWatcher for the specified remote.
	RemoteWatcherFactory RemoteWatcherFactory

	mtx sync.Mutex
	// remoteWatchers is a map of all monitored IAs.
	remoteWatchers map[addr.IA]*remoteWatcherItem
}

// Register starts monitoring given AS under the specified selector.
//
//nolint:contextcheck // Internal context is only used for remoteWatcherItem
func (m *Monitor) Register(remote addr.IA, selector PathSelector) *Registration {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.ensureInitializedLocked()

	// If a monitor for the given AS does not exist, create it.
	// Otherwise, increase its reference count.
	item := m.remoteWatchers[remote]
	if item == nil {
		//nolint:contextcheck
		ctx, cancel := context.WithCancel(context.Background())
		item = &remoteWatcherItem{
			RemoteWatcher: m.RemoteWatcherFactory.New(remote),
			refCount:      1,
			remote:        remote,
			cancel:        cancel,
		}
		m.remoteWatchers[remote] = item
		go func() {
			defer log.HandlePanic()
			item.Run(ctx)
		}()
	} else {
		item.refCount++
	}
	return &Registration{
		monitor:       m,
		remoteWatcher: item,
		pathSelector:  selector,
	}
}

func (m *Monitor) ensureInitializedLocked() {
	if m.remoteWatchers != nil {
		return
	}
	m.remoteWatchers = make(map[addr.IA]*remoteWatcherItem)
}

func (m *Monitor) unregister(remoteWatcher *remoteWatcherItem) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	// If the monitor for the IA is not needed any more, remove it.
	remoteWatcher.refCount--
	if remoteWatcher.refCount == 0 {
		remoteWatcher.cancel()
		delete(m.remoteWatchers, remoteWatcher.remote)
	}
}

// remoteWatcherItem is a helper structure that augments RemoteWatcher with
// Monitor specific metadata.
type remoteWatcherItem struct {
	RemoteWatcher
	remote addr.IA
	// refCount keeps track of how many references to this object there are.
	refCount int
	cancel   context.CancelFunc
}
