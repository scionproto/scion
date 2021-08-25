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
)

const retryInterval = 500 * time.Millisecond

// WaitForNetworkReady checks that all IPs listed in the argument can be bound
// to. This function blocks until all IPs can be bound. Nil IPs in the input
// list are ignored.
//
// Note in general this function is called directly by the application launcher,
// and therefore doesn't need to be used. It is public for applications that
// have custom constraints when the call should happen.
func WaitForNetworkReady(ctx context.Context, ips []net.IP) {
	for i, ip := range ips {
		if ip == nil {
			ips = append(ips[:i], ips[i+1:]...)
		}
	}
	if len(ips) == 0 {
		return
	}
	log.Info("Waiting for network to be ready", "ips", ips)
	for _, ip := range ips {
		waitForIPReady(ctx, ip)
	}
	log.Info("Network ready")
}

func waitForIPReady(ctx context.Context, ip net.IP) {
	for {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip})
		if err == nil {
			listener.Close()
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryInterval):
		}
	}

}
