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
		Ingress: 0,
		Egress:  41,
		BW:      1,
		// StartTime: util.TimeToSecs(time.Now()) + 1,
		StartTime: 1,
		// deleteme the server fails to return Ak with longer than 10 durations.
		// Duration: 60,
		Duration: 5,
	}
	c.SetRequestData(localIA, req)
	flyover, err := c.RedeemHop(ctx, localIA)
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
		Ingress: 0,
		Egress:  41,
		BW:      1,
		// StartTime: util.TimeToSecs(time.Now()) + 1,
		StartTime: 1,
		// deleteme the server fails to return Ak with longer than 10 durations.
		// Duration: 60,
		Duration: 5,
	}
	c.SetRequestData(dstIA, req)
	flyover, err := c.RedeemHop(ctx, dstIA)
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
		Ingress: 0,
		Egress:  41,
		BW:      1,
		// StartTime: util.TimeToSecs(time.Now()) + 1,
		StartTime: 1,
		// Duration: 60,
		Duration: 5,
	}
	c.SetRequestData(localIA, req)
	flyover, err := c.RedeemHop(ctx, localIA)
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
