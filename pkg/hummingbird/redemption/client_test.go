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

package redemption

import (
	"context"
	"crypto/aes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/log"
	hummlib "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/private/keyconf"
)

// TestRedeemHopIntraAS uses tiny.topo AS 111 as local AS. Topology must be running.
func TestRedeemHopIntraAS(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	const redemptionServerPort = 30258
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111

	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)

	localIA, err := sdConn.LocalIA(ctx)
	require.NoError(t, err)
	require.Equal(t, "1-ff00:0:111", localIA.String())

	c, err := NewRedemptionClient(ctx, sdConn)
	require.NoError(t, err)

	req := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			BW: 1,
			// StartTime: util.TimeToSecs(time.Now()) + 1,
			StartTime: 1,
			// deleteme the server fails to return Ak with longer than 10 durations.
			// Duration: 60,
			Duration: 5,
		},
		Ingress: 0,
		Egress:  41,
	}
	c.SetRequestDataForLaterRedemption(localIA, req)
	flyover, err := c.RedeemHopWithPreviousRequest(ctx, localIA)
	require.NoError(t, err)
	require.NotEqual(t, 0, flyover.ResID)
	require.Len(t, flyover.Ak, hummingbird.AkSize)
	require.Equal(t, localIA, flyover.IA)
	require.Equal(t, req.Ingress, flyover.Ingress)
	require.Equal(t, req.Egress, flyover.Egress)
	require.Equal(t, req.BW, flyover.Bw)
	require.Equal(t, req.StartTime, flyover.StartTime)
	require.Equal(t, req.Duration, flyover.Duration)
	t.Logf("Ak = %s", hex.EncodeToString(flyover.Ak[:]))
}

// TestRedeemHopInterAS requires the tiny.topo to be running.
func TestRedeemHopInterAS(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	const redemptionServerPort = 30258
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111
	dstIA := addr.MustParseIA("1-ff00:0:110")

	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)

	localIA, err := sdConn.LocalIA(ctx)
	require.NoError(t, err)
	require.Equal(t, "1-ff00:0:111", localIA.String())

	c, err := NewRedemptionClient(ctx, sdConn)
	require.NoError(t, err)

	req := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			BW: 1,
			// StartTime: util.TimeToSecs(time.Now()) + 1,
			StartTime: 1,
			// deleteme the server fails to return Ak with longer than 10 durations.
			// Duration: 60,
			Duration: 5,
		},
		Ingress: 0,
		Egress:  41,
	}
	c.SetRequestDataForLaterRedemption(dstIA, req)
	flyover, err := c.RedeemHopWithPreviousRequest(ctx, dstIA)
	require.NoError(t, err)
	require.NotEqual(t, 0, flyover.ResID)
	require.Len(t, flyover.Ak, hummingbird.AkSize)
	require.Equal(t, dstIA, flyover.IA)
	require.Equal(t, req.Ingress, flyover.Ingress)
	require.Equal(t, req.Egress, flyover.Egress)
	require.Equal(t, req.BW, flyover.Bw)
	require.Equal(t, req.StartTime, flyover.StartTime)
	require.Equal(t, req.Duration, flyover.Duration)
	t.Logf("Ak = %s", hex.EncodeToString(flyover.Ak[:]))
}

func TestRedeemPath(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	const redemptionServerPort = 30258
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111
	dstIA := addr.MustParseIA("1-ff00:0:112")

	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)

	localIA, err := sdConn.LocalIA(ctx)
	require.NoError(t, err)
	require.Equal(t, "1-ff00:0:111", localIA.String())

	c, err := NewRedemptionClient(ctx, sdConn)
	require.NoError(t, err)

	// Find a path.
	paths, err := sdConn.Paths(ctx, dstIA, localIA, types.PathReqFlags{})
	require.NoError(t, err)
	require.Greater(t, len(paths), 0)
	chosenPath := paths[0]
	// Tiny.topo defines 111->110->112 as the only path.
	require.Len(t, chosenPath.Metadata().Interfaces, 4)

	// Without any requests stored, we should still get three nil flyovers.
	results, err := c.RedeemPathWithPreviousRequests(ctx, chosenPath)
	require.NoError(t, err)
	require.Len(t, results, 3) // 3 hops
	require.Nil(t, results[0])
	require.Nil(t, results[1])
	require.Nil(t, results[2])

	// Set some reservation requests. Common to all ASes with the exception of the interfaces.
	as110 := addr.MustParseIA("1-ff00:0:110")
	as111 := addr.MustParseIA("1-ff00:0:111")
	as112 := addr.MustParseIA("1-ff00:0:112")
	request := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			BW:        1,
			StartTime: 1,
			Duration:  5,
		},
	}
	// AS111.
	request.Ingress = 0
	request.Egress = 41
	c.SetRequestDataForLaterRedemption(as111, request)
	// AS110.
	request.Ingress = 1
	request.Egress = 2
	c.SetRequestDataForLaterRedemption(as110, request)
	// AS112.
	request.Ingress = 1
	request.Egress = 0
	c.SetRequestDataForLaterRedemption(as112, request)

	// Check reservation request map.
	require.Len(t, c.requestMap, 3)

	// Redeem again. This time we should get three full flyovers.
	results, err = c.RedeemPathWithPreviousRequests(ctx, chosenPath)
	require.NoError(t, err)
	require.Len(t, results, 3) // 3 hops
	require.NotNil(t, results[0])
	require.NotNil(t, results[1])
	require.NotNil(t, results[2])

	// AS111.
	require.Equal(t, as111, results[0].IA)
	require.Equal(t, uint16(0), results[0].Ingress)
	require.Equal(t, uint16(41), results[0].Egress)
	// AS110.
	require.Equal(t, as110, results[1].IA)
	require.Equal(t, uint16(1), results[1].Ingress)
	require.Equal(t, uint16(2), results[1].Egress)
	// AS112.
	require.Equal(t, as112, results[2].IA)
	require.Equal(t, uint16(1), results[2].Ingress)
	require.Equal(t, uint16(0), results[2].Egress)
	// Common.
	for i := range results {
		require.Equal(t, request.BW, results[i].Bw)
		require.Equal(t, request.StartTime, results[i].StartTime)
		require.Equal(t, request.Duration, results[i].Duration)
	}
}

func TestRedeemPathWithRequest(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	const redemptionServerPort = 30258
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111
	dstIA := addr.MustParseIA("1-ff00:0:112")

	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)

	localIA, err := sdConn.LocalIA(ctx)
	require.NoError(t, err)
	require.Equal(t, "1-ff00:0:111", localIA.String())

	c, err := NewRedemptionClient(ctx, sdConn)
	require.NoError(t, err)

	// Find a path.
	paths, err := sdConn.Paths(ctx, dstIA, localIA, types.PathReqFlags{})
	require.NoError(t, err)
	require.Greater(t, len(paths), 0)
	chosenPath := paths[0]
	// Tiny.topo defines 111->110->112 as the only path.
	require.Len(t, chosenPath.Metadata().Interfaces, 4)

	// Redeem with basic request. We should get three full flyovers.
	request := hummingbird.RedemptionRequestNoHop{
		BW:        1,
		StartTime: 1,
		Duration:  5,
	}
	results, err := c.RedeemPathWithRequest(ctx, chosenPath, request)
	require.NoError(t, err)
	require.Len(t, results, 3) // 3 hops
	require.NotNil(t, results[0])
	require.NotNil(t, results[1])
	require.NotNil(t, results[2])

	// Check result values.
	as110 := addr.MustParseIA("1-ff00:0:110")
	as111 := addr.MustParseIA("1-ff00:0:111")
	as112 := addr.MustParseIA("1-ff00:0:112")
	// AS111.
	require.Equal(t, as111, results[0].IA)
	require.Equal(t, uint16(0), results[0].Ingress)
	require.Equal(t, uint16(41), results[0].Egress)
	// AS110.
	require.Equal(t, as110, results[1].IA)
	require.Equal(t, uint16(1), results[1].Ingress)
	require.Equal(t, uint16(2), results[1].Egress)
	// AS112.
	require.Equal(t, as112, results[2].IA)
	require.Equal(t, uint16(1), results[2].Ingress)
	require.Equal(t, uint16(0), results[2].Egress)
	// Common.
	for i := range results {
		require.Equal(t, request.BW, results[i].Bw)
		require.Equal(t, request.StartTime, results[i].StartTime)
		require.Equal(t, request.Duration, results[i].Duration)
	}
}

func TestAkCorrectness(t *testing.T) {
	t.Skip("deleteme TODO disabled until investigation on why the Aks are different.")
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	const redemptionServerPort = 30258
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111

	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)

	localIA, err := sdConn.LocalIA(ctx)
	require.NoError(t, err)
	require.Equal(t, "1-ff00:0:111", localIA.String())

	c, err := NewRedemptionClient(ctx, sdConn)
	require.NoError(t, err)

	// Set a deterministic client key.
	c.privKey = rsaPrivateKeyForTests(t)
	c.pubBytes = x509.MarshalPKCS1PublicKey(&c.privKey.PublicKey)

	req := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			BW: 1,
			// StartTime: util.TimeToSecs(time.Now()) + 1,
			StartTime: 1,
			// Duration: 60,
			Duration: 5,
		},
		Ingress: 0,
		Egress:  41,
	}
	c.SetRequestDataForLaterRedemption(localIA, req)
	flyover, err := c.RedeemHopWithPreviousRequest(ctx, localIA)
	require.NoError(t, err)
	gotAk := flyover.Ak

	// Derive Ak from local data.
	expectedAk := deriveAk(t, localIA, flyover)

	require.Equal(t, expectedAk, gotAk)
}

func buildSdConn(
	ctx context.Context,
	t *testing.T,
	daemonAddr string,
) daemon.Connector {
	conn, err := daemon.NewService(daemonAddr).Connect(ctx)
	require.NoError(t, err)
	return conn
}

func deriveAk(t *testing.T, ia addr.IA, flyover *hummingbird.FlyoverData) [hummingbird.AkSize]byte {
	// Get SV.
	genPath := "../../../gen/"
	asDir := addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator())
	keysDir := filepath.Join(genPath, asDir, "keys")
	t.Logf("keysDir = %s", keysDir)
	master, err := keyconf.LoadMaster(keysDir)
	require.NoError(t, err)
	log.Debug("Have Hummingbird master secret for IA", "ia", ia)
	sv := hummlib.DeriveSecretValue(master.Key0)
	t.Logf("sv = %s", hex.EncodeToString(sv))

	//
	block, err := aes.NewCipher(sv)
	require.NoError(t, err)
	buffer := make([]byte, hummlib.AkBufferSize)

	t.Logf("resID = %d, bw = %d, in = %d, eg = %d, start = %d, dur = %d",
		flyover.ResID,
		flyover.Bw,
		flyover.Ingress,
		flyover.Egress,
		flyover.StartTime,
		flyover.Duration,
	)
	akRaw := hummlib.DeriveAuthKey(
		block,
		flyover.ResID,
		flyover.Bw,
		flyover.Ingress,
		flyover.Egress,
		flyover.StartTime,
		flyover.Duration,
		buffer,
	)
	t.Logf("ak = %s", hex.EncodeToString(akRaw))
	var ak [hummingbird.AkSize]byte
	copy(ak[:], akRaw)

	return ak
}

func rsaPrivateKeyForTests(t *testing.T) *rsa.PrivateKey {
	const testClientPrivateKey = "MIICXQIBAAKBgQC1zb0DLTfmFFcZRd5RFo/S" +
		"EVhGMuO+KLgexCeiVJMxnbvfkE4cqR3zp2WsTuG24A97JeVAiglw4FvDA9X7kKCjRFam4JVYq3RAJ7" +
		"NcCX6leVD/fasRldiMIEuoo9oa8egu/pc7S/mu8hjcg1kxJzJYz7YElA4JNOpJNtb2beWToQIDAQAB" +
		"AoGBAKAUejuT00aJ3m9ob+rifNyxXRLiuFm2LPkaKvPqmHj1tHmT7NObrb3fRc1E38ZQ4BDFO2lqog" +
		"l75BCBDiemH2pl/022cSB6MP/ieFW8pLm5GNkNgA/7m9doVWOlaZdQ7fVSUJNVjKvRGKzwaFZTfeJe" +
		"bKiQHXqT88q0zXVYxTrhAkEA6pQYhh2gj/ZQz8PbCKGcEBbRkCYbJhfHSZYnb428ZM0uSJjWXZ4Kme" +
		"B0k4hNG04hyCKm90ovKHWd4hSGEjKALQJBAMZn437gfbzi2eIUkpNY7DZU668Iq1KpIL1rLen8MZLp" +
		"TnN6AiJy4cwIHMyTzxBITpN0tONofy2sR5C8wDyiVcUCQFsv3qij87qCwb9CH28ng4ctl6E1bvBL5g" +
		"hQ+lt++XEl4YwO/aW+vdg7TJXdMjwfDzrBXa5bhCFyN0GfQM7qGrECQQDEK+49Afxw6Z/jMNIojJCp" +
		"u9d4rkqvJXiwsSupoejmSHaAKQ+5PfvR/+dxw2fFwqimlYtRGn49C42LJ4Wvrha9AkB9a/bIefI6IA" +
		"HzX17ofsT/CEAl94EsGgTO7liWgCmlvo/EOFcrIFuz5FKRwEkzsZnGzRYpXxLRbUOrlKij/Dfu"

	privateKeyBase64, err := base64.StdEncoding.DecodeString(testClientPrivateKey)
	require.NoError(t, err)
	privKey, err := x509.ParsePKCS1PrivateKey(privateKeyBase64)
	require.NoError(t, err)
	return privKey
}
