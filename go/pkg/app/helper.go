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

package app

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

// ASInfo holds information about the local AS.
type ASInfo struct {
	IA  addr.IA
	MTU uint16
}

// QueryASInfo queries information about the local AS from SCIOND.
func QueryASInfo(ctx context.Context, conn sciond.Connector) (ASInfo, error) {
	asInfo, err := conn.ASInfo(ctx, addr.IA{})
	if err != nil {
		return ASInfo{}, err
	}
	return ASInfo{
		IA:  asInfo.Entries[0].RawIsdas.IA(),
		MTU: asInfo.Entries[0].Mtu,
	}, nil
}

// ChoosePath selects a path to the remote
func ChoosePath(ctx context.Context, conn sciond.Connector, remote addr.IA,
	interactive, refresh bool) (snet.Path, error) {

	paths, err := conn.Paths(ctx, remote, addr.IA{}, sciond.PathReqFlags{Refresh: refresh})
	if err != nil {
		return nil, serrors.WrapStr("retreiving paths", err)
	}
	if len(paths) == 0 {
		return nil, serrors.New("no path available")
	}
	if !interactive {
		return paths[rand.Intn(len(paths))], nil
	}

	fmt.Printf("Available paths to %s:\n", remote)
	for i, path := range paths {
		fmt.Printf("[%2d] %s\n", i, path)
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Choose path: ")
		pathIndexStr, _ := reader.ReadString('\n')
		idx, err := strconv.Atoi(pathIndexStr[:len(pathIndexStr)-1])
		if err == nil && int(idx) < len(paths) {
			return paths[idx], nil
		}
		fmt.Fprintf(os.Stderr, "Path index outside of valid range: [0, %v]\n", len(paths)-1)
	}
}

// WithSignal derives a child context that subsribes a signal handler for the
// provided signals. The returned context gets cancled if any of the subscribed
// signals is received
func WithSignal(ctx context.Context, sig ...os.Signal) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	stop := make(chan os.Signal, len(sig))
	signal.Notify(stop, sig...)

	go func() {
		defer log.HandlePanic()
		defer signal.Stop(stop)
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx
}
