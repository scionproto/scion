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

package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	hbconfig "github.com/scionproto/scion/hbird/config"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
	"github.com/scionproto/scion/private/config"
)

const (
	configurationDirName     = "configuration"
	testdataConfigurationDir = "testdata/" + configurationDirName
)

var update = xtest.UpdateGoldenFiles()

func TestSampleConfig(t *testing.T) {
	generatedRoot := t.TempDir()
	generatedDir := filepath.Join(generatedRoot, configurationDirName)
	require.NoError(t, os.MkdirAll(generatedDir, 0o744))
	files := map[string](func(*testing.T, string, string)){
		"hbird.toml":              writeHbird,
		"topology.json":           writeTopo,
		"dummy_keys/master0.key":  writeDummyKey,
		"dummy_keys/master1.key":  writeDummyKey,
		"dummy_keys2/master0.key": writeDummyKey2,
		"dummy_keys2/master1.key": writeDummyKey2,
	}
	for name, wFun := range files {
		path := filepath.Join(generatedDir, name)
		if _, err := os.Stat(path); err != nil {
			wFun(t, path, generatedDir)
		}
	}
	if *update {
		copyDir(t, generatedDir, testdataConfigurationDir)
	}
	compareDirs(t, testdataConfigurationDir, generatedDir)
}

func TestBwToWireFormatConversion(t *testing.T) {
	testCases := []struct {
		kbps       uint64
		wireFormat uint16
	}{
		{624, 0x0a7},
		{184549376, 0x2ec},
		{32, 0x20},
		{31, 0x1f},
		{63, 0x3f},
		{7113539584, 0x395},
		{12058624, 0x26e},
		{148, 0x65},
		{573440, 0x1e3},
		{416, 0x94},
		{92274688, 0x2cc},
		{159744, 0x1a7},
		{7247757312, 0x396},
		{2885681152, 0x36b},
	}
	for _, tc := range testCases {
		got, err := FromKbps(tc.kbps).ToWireFormat()
		require.NoError(t, err)
		require.Equal(t, tc.wireFormat, got)
	}
	for _, tc := range testCases {
		gotBW, err := FromWireFormat(tc.wireFormat)
		require.NoError(t, err)
		expected := FromKbps(tc.kbps)
		require.Equal(t, expected, gotBW)
	}
}

func TestResIDBoundCheck(t *testing.T) {
	testCases := []struct {
		resID uint32
		valid bool
	}{
		{0, true},
		{1, true},
		{4096, true},
		{uint32(1)<<RESID_BITS - 1, true},
		{uint32(1) << RESID_BITS, false},
		{(uint32(1) << RESID_BITS) - 1, true},
		{4194303, true},
		{4194304, false},
	}
	for _, tc := range testCases {
		r := ResInfo{}
		r, err := r.WithResID(tc.resID)
		if tc.valid != (err == nil) {
			t.Errorf("WithResID(0x%x) got %v; want %v", tc.resID, err == nil, tc.valid)
		}
	}
}

func TestBandwidthEncodingOverflow(t *testing.T) {
	testCases := []struct {
		bw    uint64
		valid bool
	}{
		{0, true},
		{1, true},
		{1<<BW_EXP_BITS - 1, true},
		{1 << (BW_EXP_BITS * 8), false},
	}
	for _, tc := range testCases {
		bandwidth := FromKbps(tc.bw)
		wf, err := bandwidth.ToWireFormat()
		if !tc.valid {
			require.Error(t, err)
			_, err = FromWireFormat(1<<16 - 1)
			require.Error(t, err)
			// Catch invalid BW in Ak computation
			masterKey, _ := base64.StdEncoding.DecodeString(dummy_keys_master0)
			_, err = ComputeAuthenticationKey(
				ResInfo{Bandwidth: Bandwidth{kbps: tc.bw}},
				([16]byte)(masterKey))
			require.Error(t, err)
			continue
		} else {
			require.NoError(t, err)

		}

		// convert back
		bandwidth2, err := FromWireFormat(wf)
		require.NoError(t, err)
		require.Equal(t, bandwidth, bandwidth2)
	}
}

func TestAuthKeyComputation(t *testing.T) {
	path := filepath.Join(testdataConfigurationDir, "dummy_keys2")
	masterKey := loadHBMasterSecret(path)

	// Create the service
	svc := NewHummingbirdKeyDerivationService(masterKey)

	// Create a ResInfo
	bw := FromKbps(1200) // 1.2 Mbps
	start := time.Unix(100_000, 0)
	dur := 3600 * time.Second
	isdAs := addr.MustParseIA("1-0000:0000:0110")

	res := NewResInfo(isdAs, 2, 5, bw, start, dur)

	// Check ResInfo
	err := res.Check()
	require.NoError(t, err)

	// Compute ResID
	res, err = res.WithResID(0x123) // in range for 22 bits
	require.NoError(t, err)

	// Compute A_k authentication key
	completeReservation, err := svc.AssignAuthenticationKey(res)
	require.NoError(t, err)

	fmt.Printf("Derived auth key: %x\n", completeReservation.AuthenticationKey)
	expectedAk := []byte{0x32, 0x1e, 0xcb, 0x05, 0x69, 0xaf, 0x49, 0x2f, 0x58, 0x4b, 0x59, 0xc6,
		0x60, 0x4f, 0x78, 0xe2}
	require.Equal(t, expectedAk, completeReservation.AuthenticationKey)
	var expectedBWP uint64 = 4320000
	require.Equal(t, expectedBWP, completeReservation.ResInfo.TimeBandwidthProductKb())
}

func TestRedemption(t *testing.T) {
	return
}

func TestClientEncryption(t *testing.T) {
	authenticationKey, err := base64.StdEncoding.DecodeString(testAuthKey)
	require.NoError(t, err)
	clientKey, err := base64.StdEncoding.DecodeString(testClientPublicKey)
	require.NoError(t, err)
	encryptedAk, err := clientEncrypt(clientKey, authenticationKey)
	require.NoError(t, err)
	decryptedAk := clientDecryptTesting(t, encryptedAk)
	require.Equal(t, authenticationKey, decryptedAk)
}

func clientDecryptTesting(t *testing.T, cipher []byte) (plaintext []byte) {
	t.Helper()
	clientPrivateKey, err := base64.StdEncoding.DecodeString(testClientPrivateKey)
	require.NoError(t, err)
	privKey, err := x509.ParsePKCS1PrivateKey(clientPrivateKey)
	require.NoError(t, err)
	plainText, err := rsa.DecryptOAEP(sha256.New(), nil, privKey, cipher, nil)
	require.NoError(t, err)
	return plainText
}

func TestExample(t *testing.T) {
	ExampleHbirdAuthKeyDerivation()
}

func TestLocalServerClientIntegration(t *testing.T) {
	withWorkDir(t, "testdata")
	require.NoError(t, config.LoadFile(filepath.Join(configurationDirName, "hbird.toml"), &globalCfg))

	ctx, srvCancel := context.WithCancel(context.Background())
	srvErrCh := make(chan error, 1)
	// Run server
	go func() {
		srvErrCh <- realMain(ctx)
	}()
	time.Sleep(2 * time.Second)
	select {
	case err := <-srvErrCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("hummingbird service realMain() failed: %v", err)
		}
	default:
	}
	var err error
	// Client queries here:

	// Status
	fmt.Println("Checking status")
	err = returnStatus()
	require.NoError(t, err)

	// Redeem
	fmt.Printf("\nChecking redemption\n\n")
	rreqs := &hbirdv1.RedemptionRequests{
		Redemption: []*hbirdv1.RedemptionRequest{
			&hbirdv1.RedemptionRequest{
				RedInfo: &hbirdv1.RedemptionInfo{
					Ingress:   1,
					Egress:    2,
					Bw:        100,
					StartTime: 2000,
					Duration:  5,
				},
				IngressToken: mustDecodeBase64(t, "qL8dQkuHMbFSaQ=="),
				EgressToken:  mustDecodeBase64(t, "LoRzIDXu6k8GjA=="),
			},
		},
		ClientKey: mustDecodeBase64(t, testClientPublicKey),
	}
	marshaler := protojson.MarshalOptions{UseProtoNames: true}
	jsonRedemptionReq, err := marshaler.Marshal(rreqs)
	require.NoError(t, err)
	reqBody := bytes.NewBuffer(jsonRedemptionReq)

	if strings.Replace(reqBody.String(), " ", "", -1) != testRedemptionBodyStr {
		t.Fatalf("RedemptionRequest encoding error: got %v;want %v",
			reqBody.String(), testRedemptionBodyStr)
	}

	resp, err := sendRedeem(reqBody.String())
	require.NoError(t, err)
	rresp := &hbirdv1.RedemptionResponses{
		Reservation: []*hbirdv1.Reservation{
			&hbirdv1.Reservation{
				Ia:      0,
				ResId:   0,
				AuthKey: []byte{},
			},
		},
	}
	protojson.Unmarshal(resp, rresp)
	decryptedAuthKey := clientDecryptTesting(t, rresp.Reservation[0].AuthKey)
	require.Equal(t, testAuthKey, base64.StdEncoding.EncodeToString(decryptedAuthKey))
	fmt.Printf("\nDecrypted AuthenticationKey matches expected key\n")
	resInfo := ResInfo{
		IA:               addr.IA(rresp.Reservation[0].GetIa()),
		IngressInterface: uint16(rreqs.Redemption[0].RedInfo.GetIngress()),
		EgressInterface:  uint16(rreqs.Redemption[0].RedInfo.GetEgress()),
		ResID:            rresp.Reservation[0].GetResId(),
		Bandwidth:        FromKbps(uint64(rreqs.Redemption[0].RedInfo.GetBw())),
		StartTime:        time.Unix(int64(rreqs.Redemption[0].RedInfo.GetStartTime()), 0),
		Duration:         mustParseDuration(t, uint64(rreqs.Redemption[0].RedInfo.GetDuration())),
	}
	masterKey, _ := base64.StdEncoding.DecodeString(dummy_keys_master0)
	checkResInfo(t, resInfo, ([16]byte)(masterKey), decryptedAuthKey)
	fmt.Println("Decrypted AuthenticationKey matches reservation info")

	// Check invalid client key
	rreqs.ClientKey = []byte{0}
	jsonRedemptionReq, err = marshaler.Marshal(rreqs)
	require.NoError(t, err)
	reqBody = bytes.NewBuffer(jsonRedemptionReq)
	resp, err = sendRedeem(reqBody.String())
	require.Error(t, err)

	// Check not implemented
	fmt.Printf("\nChecking not implemented\n")
	checkNotImplementedProcedure(t)
	fmt.Printf("\nChecking wrong endpoint\n")
	checkNotImplementedEndpoint(t)

	// Send cancel to server
	srvCancel()
	fmt.Printf("\nTerminating server.\n")
	select {
	case err := <-srvErrCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("hummingbird service realMain() failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out while waiting for server shutdown")
	}
	fmt.Println("Sent server shutdown signal.")
	time.Sleep(2 * time.Second)
	// Check status against shutdown server
	fmt.Printf("\nChecking against shutdown server\n")
	err = returnStatus()
	require.Error(t, err)
	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr)
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
	fmt.Printf("Got expected connection error\n\n")
	fmt.Println("TestServerClientIntegration completed")
}

func returnStatus() error {
	requestURL := fmt.Sprintf("http://localhost:%d%s",
		serverPort, hbirdv1connect.HBirdServiceStatusProcedure)
	bodyStr := `{}`
	_, err := query(requestURL, bodyStr, false)
	return err
}

func checkNotImplementedProcedure(t *testing.T) {
	requestURL := fmt.Sprintf("http://localhost:%d%s2",
		serverPort, hbirdv1connect.HBirdServiceStatusProcedure)
	bodyStr := `{}`
	_, err := query(requestURL, bodyStr, false)
	checkErrIsStatusNotFound(t, err)
}

func checkNotImplementedEndpoint(t *testing.T) {
	requestURL := fmt.Sprintf("http://localhost:%d/Status", serverPort)
	bodyStr := `{}`
	_, err := query(requestURL, bodyStr, false)
	checkErrIsStatusNotFound(t, err)
}

func checkErrIsStatusNotFound(t *testing.T, err error) {
	require.Error(t, err)
	require.True(t, strings.HasSuffix(err.Error(), fmt.Sprint(http.StatusNotFound)),
		"got error: %v, expected: %v", err, http.StatusNotFound)
}

func checkResInfo(
	t *testing.T,
	resInfo ResInfo,
	masterKey [16]byte,
	expectedAk []byte) {
	gotAk, err := ComputeAuthenticationKey(resInfo, masterKey)
	require.NoError(t, err)
	require.Equal(t, expectedAk, gotAk[:])
}

func sendRedeem(redeemBody string) ([]byte, error) {
	requestURL := fmt.Sprintf("http://localhost:%d%s",
		serverPort, hbirdv1connect.HBirdServiceRedeemProcedure)
	bodyStr := redeemBody
	return query(requestURL, bodyStr, true)
}

func query(requestURL, bodyStr string, checkResponse bool) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(bodyStr)
	res, err := http.Post(requestURL, "application/json", bytes.NewReader(b.Bytes()))
	if err != nil {
		return nil, err
	}
	pathSegments := strings.Split(requestURL, "/")
	procedureName := pathSegments[len(pathSegments)-1]
	fmt.Printf("%s response status: %d\n", procedureName, res.StatusCode)
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("wrong status code: %d", res.StatusCode)
	}
	response, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	fmt.Printf("%s response: %s\n", procedureName, response)
	return response, nil
}

func mustDecodeBase64(t *testing.T, s string) []byte {
	var b []byte
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func mustParseDuration(t *testing.T, i uint64) time.Duration {
	duration, err := time.ParseDuration(fmt.Sprintf("%ds", i))
	require.NoError(t, err)
	return duration
}

func withWorkDir(t *testing.T, dir string) {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})
}

func copyDir(t *testing.T, src, dst string) {
	err := os.RemoveAll(dst)
	require.NoError(t, err)
	err = os.MkdirAll(dst, 0o755)
	require.NoError(t, err)
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		rel, err := filepath.Rel(src, path)
		require.NoError(t, err)
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		return os.WriteFile(target, data, 0o644)
	})
	require.NoError(t, err)
}

func compareDirs(t *testing.T, expected, actual string) {
	expectedFiles := readDirFiles(t, expected)
	actualFiles := readDirFiles(t, actual)

	require.Equal(t, expectedFiles, actualFiles)
	for _, rel := range expectedFiles {
		expectedContent, err := os.ReadFile(filepath.Join(expected, rel))
		require.NoError(t, err)
		actualContent, err := os.ReadFile(filepath.Join(actual, rel))
		require.NoError(t, err)
		require.Equal(t, expectedContent, actualContent)
	}
}

func readDirFiles(t *testing.T, root string) []string {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		files = append(files, rel)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(files)
	return files
}

func writeHbird(t *testing.T, path, testConfigDir string) {
	cfg, err := generateHBSampleConfig()
	require.NoError(t, err)
	// update config for tests
	cfg.Logging.Console.Level = "debug"
	cfg.General.ConfigDir = configurationDirName

	// write out HB config
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	var sample bytes.Buffer
	err = toml.NewEncoder(&sample).Encode(cfg)
	require.NoError(t, err)
	_, err = f.Write(sample.Bytes())
	require.NoError(t, err)
}

func writeTopo(t *testing.T, path, _ string) {
	// write out topo file
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	var b bytes.Buffer
	b.WriteString(sampleTopology)
	_, err = f.Write(b.Bytes())
	require.NoError(t, err)
}

func writeDummyKey(t *testing.T, path, testConfigDir string) {
	dummyKeysDir := filepath.Join(testConfigDir, "dummy_keys")
	var payload string
	if strings.HasSuffix(path, "master0.key") {
		payload = dummy_keys_master0
	}
	if strings.HasSuffix(path, "master1.key") {
		payload = dummy_keys_master1
	}
	writeDummyKeys(t, path, dummyKeysDir, payload)
}

func writeDummyKey2(t *testing.T, path, testConfigDir string) {
	dummyKeysDir := filepath.Join(testConfigDir, "dummy_keys2")
	var payload string
	if strings.HasSuffix(path, "master0.key") {
		payload = dummy_keys2_master0
	}
	if strings.HasSuffix(path, "master1.key") {
		payload = dummy_keys2_master1
	}
	writeDummyKeys(t, path, dummyKeysDir, payload)
}

func writeDummyKeys(t *testing.T, path, dummyKeysDir, payload string) {
	if _, err := os.Stat(dummyKeysDir); err != nil {
		err = os.Mkdir(dummyKeysDir, 0744)
		require.NoError(t, err)
	}
	// write out dummy key
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	var b bytes.Buffer
	b.WriteString(payload)
	_, err = f.Write(b.Bytes())
	require.NoError(t, err)
}

func generateHBSampleConfig() (hbconfig.Config, error) {
	var sample bytes.Buffer
	var sampleCfg hbconfig.Config
	cfg := &sampleCfg
	cfg.InitDefaults()
	cfg.Sample(&sample, nil, nil)

	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	return sampleCfg, err
}

const testRedemptionBodyStr = "{\"redemption\":[{\"red_info\":" +
	"{\"ingress\":1,\"egress\":2,\"bw\":100,\"start_time\":2000,\"duration\":5}," +
	"\"ingress_token\":\"qL8dQkuHMbFSaQ==\",\"egress_token\":\"LoRzIDXu6k8GjA==\"}]," +
	"\"client_key\":\"MIGJAoGBALXNvQMtN+YUVxlF3lEWj9IRWEYy474ouB7EJ6JUkzGdu9+QThypHf" +
	"OnZaxO4bbgD3sl5UCKCXDgW8MD1fuQoKNEVqbglVirdEAns1wJfqV5UP99qxGV2IwgS6ij2hrx6C7+l" +
	"ztL+a7yGNyDWTEnMljPtgSUDgk06kk21vZt5ZOhAgMBAAE=\"}"
const testRedemptionResp = "{\"reservation\":" +
	"[{\"ia\":\"281474976710756\",\"authKey\":" +
	"\"BrGjgXU5xayVHJl+Tf9l8VgKFZ77Q54BKl4gVCvftfXIshdzug0XTdlBFMLdne02mSyhqOWT3LQA/" +
	"vpdAk8xwBNIMxvYRlTUQgJzOcqmnqd8Mdcg8MknsOrDtRfKB1y/7Iv8174n2O1bZ2hvAhiRNjZwZwpf" +
	"iTmpeiwnh7pZ3qw=\"}]}"
const testAuthKey = "lMLm7i/xoWQEiJNTVlABlQ=="

const testClientPublicKey = "MIGJAoGBALXNvQMtN+YUVxlF3lEWj9IRWE" +
	"Yy474ouB7EJ6JUkzGdu9+QThypHfOnZaxO4bbgD3sl5UCKCXDgW8MD1fuQoKNEVqbglVirdEAns1wJ" +
	"fqV5UP99qxGV2IwgS6ij2hrx6C7+lztL+a7yGNyDWTEnMljPtgSUDgk06kk21vZt5ZOhAgMBAAE="
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
const sampleTopology = `
{
  "isd_as": "1-100",
  "mtu": 1472,
  "attributes": [],
  "dispatched_ports": "31000-32767",
  "border_routers": {
    "br1-100-1": {
      "internal_addr": "127.0.0.20:30042",
      "ctrl_addr": "127.0.0..20:30242",
      "interfaces": {
        "1": {
          "underlay": {
            "public": "169.254.1.2:30042",
            "remote": "169.254.1.1:30042"
          },
          "bandwidth": 1000,
          "isd_as": "1-200",
          "link_to": "PARENT",
          "mtu": 1472
        }
      }
    }
  },
  "control_service": {
    "cs1-100-1": {
      "addr": "127.0.0.20:30252"
    },
    "cs1-100-2": {
      "addr": "127.0.0.35:30252"
    }
  },
  "discovery_service": {
    "ds1-100-1": {
      "addr": "127.0.0.20:30252"
    }
  },
  "sigs": {
    "sig64-2_0_9-1": {
      "ctrl_addr": "127.0.0.19:30256",
      "data_addr": "127.0.0.19:30056"
    }
  }
}`
const dummy_keys_master0 = `Q7dc0ap9/VeSjqJNbFI5Hw==`
const dummy_keys_master1 = `7ncpfi4DmIa08XeI1EMGmg==`
const dummy_keys2_master0 = `AAECAwQFBgcICQoLDA0ODw==`
const dummy_keys2_master1 = `MDAwMDAwMDAwMDAwMDAwMA==`
