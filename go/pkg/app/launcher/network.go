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

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// WaitForNetworkReady checks that all IPs listed in the argument can be bound
// to. This function blocks until either all IPs can be bound to or the context
// expires. The error is nil if all IPs can be bound to. If the error is non nil
// it will contain the IPs for which the binding failed. Nil IPs in the input
// list are ignored.
//
// Note in general this function is called directly by the application launcher,
// and therefore doesn't need to be used. It is public for applications that
// have custom constraints when the call should happen.
func WaitForNetworkReady(ctx context.Context, ips []net.IP) error {
	for i, ip := range ips {
		if ip == nil {
			ips = append(ips[:i], ips[i+1:]...)
		}
	}
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
		previousMissingIPs = checkNetwork(ctx, ips)
	}
	return nil
}

func checkNetwork(ctx context.Context, ips []net.IP) []string {
	missingIPs := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		missingIPs[ip.String()] = ip
	}
	cfg := net.ListenConfig{}
	for k := range missingIPs {
		listener, err := cfg.Listen(ctx, "tcp", net.JoinHostPort(k, "0"))
		if err != nil {
			continue
		}
		listener.Close()
		delete(missingIPs, k)
	}
	return keysToList(missingIPs)
}

func keysToList(m map[string]net.IP) []string {
	keys := make([]string, 0, len(m))
	for ip := range m {
		keys = append(keys, ip)
	}
	return keys
}
