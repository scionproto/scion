// Copyright 2020 Anapaya Systems

package svchealth

import (
	"context"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
)

var supportedServices = []addr.HostSVC{addr.SvcDS, addr.SvcCS, addr.SvcSIG}

// Discoverer discovers healthy service instances of different types.
type Discoverer interface {
	Discover(ctx context.Context, svc addr.HostSVC) ([]*net.UDPAddr, error)
	Discoverable(svc addr.HostSVC) bool
}

// Watcher watches for service changes in the topology.
type Watcher struct {
	Discoverer Discoverer
	Topology   topology.Topology

	mtx  sync.Mutex
	prev map[addr.HostSVC][]*net.UDPAddr
}

// Discover discovers a service health differential update based on the health
// discoverer. Every service, where healthy discovery fails, falls back to the
// configured topology. The initial diff is based on the configured topology. It
// is safe to concurrent access.
func (w *Watcher) Discover(ctx context.Context) (Diff, error) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	// initialize previous mapping on first run.
	if w.prev == nil {
		m := make(map[addr.HostSVC][]*net.UDPAddr)
		for _, svc := range supportedServices {
			var err error
			if !w.svcExists(svc) {
				continue
			}
			if m[svc], err = w.Topology.UnderlayMulticast(svc); err != nil {
				return Diff{}, serrors.WrapStr("initializing watcher", err)
			}
		}
		w.prev = m
	}
	curr, err := w.discover(ctx)
	if err != nil {
		return Diff{}, err
	}
	diff := ComputeDiff(w.prev, curr)
	w.prev = curr
	return diff, nil
}

func (w *Watcher) discover(ctx context.Context) (map[addr.HostSVC][]*net.UDPAddr, error) {
	var wg sync.WaitGroup
	discAddrs := make([][]*net.UDPAddr, len(supportedServices))
	for i, svc := range supportedServices {
		if !w.Discoverer.Discoverable(svc) {
			continue
		}
		wg.Add(1)
		go func(i int, svc addr.HostSVC) {
			defer log.HandlePanic()
			defer wg.Done()
			addrs, err := w.Discoverer.Discover(ctx, svc)
			if err != nil {
				log.FromCtx(ctx).Debug("Failed to discover, falling back", "svc", svc, "err", err)
				return
			}
			if len(addrs) == 0 && w.svcExists(svc) {
				log.FromCtx(ctx).Debug("No healthy instance discovered, falling back", "svc", svc)
				return
			}
			for i := range addrs {
				addrs[i].Port = topology.EndhostPort
			}
			discAddrs[i] = addrs
		}(i, svc)
	}
	wg.Wait()

	m := make(map[addr.HostSVC][]*net.UDPAddr)
	for i, svc := range supportedServices {
		addrs := discAddrs[i]
		if len(addrs) == 0 && w.svcExists(svc) {
			var err error
			if addrs, err = w.Topology.UnderlayMulticast(svc); err != nil {
				return nil, err
			}
		}
		m[svc] = addrs
	}
	return m, nil
}

func (w *Watcher) svcExists(svc addr.HostSVC) bool {
	return len(w.Topology.SVCNames(svc)) != 0
}

// DiscovererMap implements the Discoverer interface and allows
// registering different health discoverers per service type.
type DiscovererMap map[addr.HostSVC]interface {
	Discover(ctx context.Context, svc addr.HostSVC) ([]*net.UDPAddr, error)
}

// Discover invokes the appropriate health discoverer.
func (m DiscovererMap) Discover(ctx context.Context, svc addr.HostSVC) ([]*net.UDPAddr, error) {
	discoverer, ok := m[svc]
	if !ok {
		return nil, serrors.New("service not registered for discovery", "svc", svc)
	}
	return discoverer.Discover(ctx, svc)
}

// Discoverable indicates whether discovery for the service type is supported.
func (m DiscovererMap) Discoverable(svc addr.HostSVC) bool {
	_, ok := m[svc]
	return ok
}

// StaticDiscoverer returns a static set of instances.
type StaticDiscoverer struct {
	Addrs []*net.UDPAddr
}

// Discover returns a static set of instances.
func (s StaticDiscoverer) Discover(_ context.Context, _ addr.HostSVC) ([]*net.UDPAddr, error) {
	return s.Addrs, nil
}
