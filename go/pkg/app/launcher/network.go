// Copyright 2021 Anapaya Systems
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

package launcher

import (
	"context"
	"net"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// WaitForNetworkReady checks that all IPs have a corresponding interface on
// the host that is up. This function blocks until either all IPs have been
// found on interfaces that are up or the context expires. The error is nil if
// the interfaces have been found, otherwise it will conain details about what
// IPs have not been found on interfaces.
//
// Note in general this function is called directly by the application launcher,
// and therefore doesn't need to be used. It is public for applications that
// have custom constraints when the call should happen.
func WaitForNetworkReady(ctx context.Context, ips []net.IP) error {
	previousMissingIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		previousMissingIPs = append(previousMissingIPs, ip.String())
	}
	for i := 0; len(previousMissingIPs) > 0; i++ {
		if i > 2 {
			log.Info("Waiting for network to be ready", "missing_ips", previousMissingIPs)
		}
		select {
		case <-ctx.Done():
			return serrors.WrapStr("waiting for network ready", ctx.Err(),
				"missingIPs", previousMissingIPs)
		case <-time.After(time.Duration(i*100) * time.Millisecond):
		}
		var err error
		previousMissingIPs, err = checkNetwork(ips)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkNetwork(ips []net.IP) ([]string, error) {
	missingIPs := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		missingIPs[ip.String()] = ip
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, serrors.WrapStr("listing links", err)
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, serrors.WrapStr("listing addresses", err, "interface", link.Attrs().Name)
		}
		for _, la := range addrs {
			for k, a := range missingIPs {
				if a.Equal(la.IP) {
					delete(missingIPs, k)
				}
			}
		}
	}
	return keysToList(missingIPs), nil
}

func keysToList(m map[string]net.IP) []string {
	keys := make([]string, 0, len(m))
	for ip := range m {
		keys = append(keys, ip)
	}
	return keys
}
