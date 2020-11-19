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
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

// ASInfo holds information about the local AS.
type ASInfo struct {
	IA  addr.IA
	MTU uint16
}

// QueryASInfo queries information about the local AS from the SCION Daemon.
func QueryASInfo(ctx context.Context, conn daemon.Connector) (ASInfo, error) {
	asInfo, err := conn.ASInfo(ctx, addr.IA{})
	if err != nil {
		return ASInfo{}, err
	}
	return ASInfo{
		IA:  asInfo.IA,
		MTU: asInfo.MTU,
	}, nil
}

// Filter filters out paths according to a sequence.
func Filter(seq string, paths []snet.Path) ([]snet.Path, error) {
	s, err := pathpol.NewSequence(seq)
	if err != nil {
		return nil, err
	}
	return s.Eval(paths), nil
}

// ChoosePath selects a path to the remote.
func ChoosePath(ctx context.Context, conn daemon.Connector, remote addr.IA,
	interactive, refresh bool, seq string, cs ColorScheme) (snet.Path, error) {

	allPaths, err := conn.Paths(ctx, remote, addr.IA{}, daemon.PathReqFlags{Refresh: refresh})
	if err != nil {
		return nil, serrors.WrapStr("retrieving paths", err)
	}

	paths, err := Filter(seq, allPaths)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, serrors.New("no path available")
	}
	if !interactive {
		return paths[rand.Intn(len(paths))], nil
	}

	SortPaths(paths)

	sectionHeader := func(intfs int) {
		cs.Header.Printf("%d Hops:\n", (intfs/2)+1)
	}

	fmt.Printf("Available paths to %s:\n", remote)
	sectionHeader(len(paths[0].Metadata().Interfaces))
	for i, path := range paths {
		if i != 0 && len(paths[i-1].Metadata().Interfaces) != len(path.Metadata().Interfaces) {
			sectionHeader(len(path.Metadata().Interfaces))
		}
		pathDesc := cs.KeyValues(
			"Hops", cs.Path(path),
			"MTU", fmt.Sprint(path.Metadata().MTU),
			"NextHop", fmt.Sprint(path.UnderlayNextHop()),
		)
		fmt.Printf("[%2d] %s\n", i, strings.Join(pathDesc, " "))
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Choose path: ")
		pathIndexStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
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
