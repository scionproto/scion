// Copyright 2026 ETH Zurich
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

package squic_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/snet/squic/hummingbirdtest"
)

const (
	tinyServerDaemonAddr = "127.0.0.19:30255"
	tinyClientDaemonAddr = "[fd00:f00d:cafe::7f00:b]:30255"
	tinyServerListenAddr = "1-ff00:0:111,127.0.0.20:12345"
	tinyClientListenAddr = "1-ff00:0:112,[fd00:f00d:cafe::7f00:c]:0"
	tinyServerRemoteAddr = "1-ff00:0:111,127.0.0.20:12345"
)

// TestQUICOverHummingbirdTinyTopology verifies that a QUIC handshake plus a
// stream exchange succeeds when the client sends over a Hummingbird reservation
// path in the running tiny topology.
func TestQUICOverHummingbirdTinyTopology(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live tiny-topology test in short mode")
	}
	if os.Getenv("SCION_RUN_LIVE_TESTS") == "" {
		t.Skip("set SCION_RUN_LIVE_TESTS=1 to run live tiny-topology tests")
	}

	keysRoot := requireTinyTopologyAssets(t)
	serverLocal, err := hummingbirdtest.MustParseUDPAddr(tinyServerListenAddr)
	require.NoError(t, err)
	clientLocal, err := hummingbirdtest.MustParseUDPAddr(tinyClientListenAddr)
	require.NoError(t, err)
	serverRemote, err := hummingbirdtest.MustParseUDPAddr(tinyServerRemoteAddr)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- hummingbirdtest.RunServer(
			ctx,
			tinyServerDaemonAddr,
			serverLocal,
			clientLocal.IA,
			t.Logf,
		)
	}()

	err = hummingbirdtest.RunClient(
		ctx,
		tinyClientDaemonAddr,
		clientLocal,
		serverRemote,
		keysRoot,
		t.Logf,
	)
	require.NoErrorf(t, err,
		"QUIC dial timed out or failed; this usually means the initial Hummingbird "+
			"packet was dropped before the server could reply")

	require.NoError(t, <-serverErr)
}

func requireTinyTopologyAssets(t *testing.T) string {
	t.Helper()

	root := filepath.Join(requireRepoRoot(t), "gen")
	keysRoot, err := hummingbirdtest.FindTinyTopologyAssets(root)
	require.NoError(t, err)
	t.Logf("using tiny-topology assets from %s", keysRoot)
	return keysRoot
}

func requireRepoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "resolve current file path")
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
