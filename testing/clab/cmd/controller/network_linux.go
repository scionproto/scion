// Copyright 2026 Anapaya Systems
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

//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/testing/clab/cmd/controller/config"
)

const (
	// linkWaitTimeout bounds how long the controller waits for a configured
	// interface to appear. containerlab creates the inter-AS link veths and
	// moves them into the node's netns only *after* the container (and thus the
	// controller, PID 1) has started, so the interface is usually absent for a
	// short moment at boot.
	linkWaitTimeout = 30 * time.Second
	// linkWaitInterval is how often the controller re-checks for the interface
	// while waiting for it to appear.
	linkWaitInterval = 250 * time.Millisecond
)

// addrStatus is one configured address and whether it is actually present on
// the live interface.
type addrStatus struct {
	addr    string
	present bool
}

// interfaceStatus is the live state of one configured interface: whether it
// exists in the netns at all, whether it is administratively up, and which of
// its configured addresses are actually assigned.
type interfaceStatus struct {
	name   string
	exists bool
	up     bool
	addrs  []addrStatus
}

// networkStatus queries the kernel (netlink, in the caller's netns) for the
// live state of each configured interface. Because the inspection CLI runs in
// the node's netns — the same one the controller configured — this reflects
// what the controller actually managed to set up, not just what was requested.
func networkStatus(eths []config.Ethernet) []interfaceStatus {
	out := make([]interfaceStatus, 0, len(eths))
	for _, eth := range eths {
		st := interfaceStatus{name: eth.Name}
		link, err := netlink.LinkByName(eth.Name)
		if err == nil {
			st.exists = true
			st.up = link.Attrs().Flags&net.FlagUp != 0

			present := map[string]bool{}
			if addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL); err == nil {
				for _, a := range addrs {
					present[a.IPNet.String()] = true
				}
			}
			for _, a := range eth.Addresses {
				// Normalise the configured address through the same parser so it
				// matches netlink's canonical IPNet string.
				key := a
				if parsed, err := netlink.ParseAddr(a); err == nil {
					key = parsed.IPNet.String()
				}
				st.addrs = append(st.addrs, addrStatus{addr: a, present: present[key]})
			}
		} else {
			// Interface missing: every configured address is absent.
			for _, a := range eth.Addresses {
				st.addrs = append(st.addrs, addrStatus{addr: a, present: false})
			}
		}
		out = append(out, st)
	}
	return out
}

// printNetworkStatus writes the live interface status as an aligned table, one
// row per configured address. The LINK column reflects whether the interface
// exists and is up; the STATUS column whether the address is actually assigned.
func printNetworkStatus(w io.Writer, statuses []interfaceStatus) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INTERFACE\tLINK\tADDRESS\tSTATUS")
	for _, st := range statuses {
		link := "missing"
		switch {
		case st.exists && st.up:
			link = "up"
		case st.exists:
			link = "down"
		}
		if len(st.addrs) == 0 {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", st.name, link, "-", "-")
			continue
		}
		for _, a := range st.addrs {
			status := "missing"
			if a.present {
				status = "present"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", st.name, link, a.addr, status)
		}
	}
	return tw.Flush()
}

// applyNetworkConfig assigns the configured addresses to each named interface
// and brings it up. It requires CAP_NET_ADMIN in the node's network namespace.
//
// It is best-effort and never fails the controller: an interface that does not
// appear within linkWaitTimeout is skipped with a warning (the controller is
// PID 1, so a hard failure would kill the node), and per-address errors are
// logged and skipped. It is also idempotent — an address already present is
// left in place — so the controller can be restarted against a live node.
func applyNetworkConfig(eths []config.Ethernet, log *slog.Logger) {
	for _, eth := range eths {
		configureInterface(eth, linkWaitTimeout, linkWaitInterval, log)
	}
}

// configureInterface waits for eth's link to appear, then adds its addresses
// and brings it up. All failures are logged and swallowed (see
// applyNetworkConfig).
func configureInterface(eth config.Ethernet, timeout, interval time.Duration, log *slog.Logger) {
	link := waitForLink(eth.Name, timeout, interval, log)
	if link == nil {
		log.Warn("interface did not appear; skipping its network setup",
			"iface", eth.Name, "timeout", timeout)
		return
	}
	for _, a := range eth.Addresses {
		addr, err := netlink.ParseAddr(a)
		if err != nil {
			log.Error("invalid address; skipping", "iface", eth.Name, "addr", a, "err", err)
			continue
		}
		// Skip Duplicate Address Detection for IPv6 addresses. DAD leaves a
		// freshly-added address "tentative" for a moment, during which a bind
		// to it fails with EADDRNOTAVAIL — which is fatal for the SCION router,
		// as it binds its underlay address at startup. The addresses are
		// pre-assigned and unique by construction, so DAD adds nothing here.
		if addr.IP.To4() == nil {
			addr.Flags |= unix.IFA_F_NODAD
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			// EEXIST means the address is already assigned; treat as success so
			// the controller can be restarted against a live node.
			if errors.Is(err, syscall.EEXIST) {
				log.Debug("address already present", "iface", eth.Name, "addr", a)
				continue
			}
			log.Error("failed to add address", "iface", eth.Name, "addr", a, "err", err)
			continue
		}
		log.Info("assigned address", "iface", eth.Name, "addr", a)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		log.Error("failed to bring link up", "iface", eth.Name, "err", err)
	}
}

// waitForLink polls for the named interface until it exists or timeout elapses,
// returning the link, or nil if it never appeared. containerlab attaches the
// link veths shortly after the node starts, so the interface is typically
// missing only for the first moment of the controller's life.
func waitForLink(name string, timeout, interval time.Duration, log *slog.Logger) netlink.Link {
	deadline := time.Now().Add(timeout)
	for waited := false; ; waited = true {
		link, err := netlink.LinkByName(name)
		if err == nil {
			if waited {
				log.Info("interface appeared", "iface", name)
			}
			return link
		}
		if time.Now().After(deadline) {
			return nil
		}
		if !waited {
			log.Info("waiting for interface to appear", "iface", name, "timeout", timeout)
		}
		time.Sleep(interval)
	}
}
