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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/scionproto/scion/hbird/hbserver/connect"
	"google.golang.org/protobuf/encoding/protojson"

	hbconfig "github.com/scionproto/scion/hbird/config"
	"github.com/scionproto/scion/pkg/addr"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
	"github.com/scionproto/scion/private/config"
)

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
	BwToWireFormat(t, testCases)
	BwFromWireFormat(t, testCases)
}

func BwToWireFormat(t *testing.T, testCases []struct {
	kbps       uint64
	wireFormat uint16
}) {
	for _, tc := range testCases {
		got, err := connect.FromKbps(tc.kbps).ToWireFormat()
		if err != nil {
			t.Fatalf("FromKbps(%d).ToWireFormat() failed: %v", tc.kbps, err)
		}
		if got != tc.wireFormat {
			t.Errorf("FromKbps(%d).ToWireFormat() = 0x%x; want 0x%x",
				tc.kbps, got, tc.wireFormat)
		}
	}
}

func BwFromWireFormat(t *testing.T, testCases []struct {
	kbps       uint64
	wireFormat uint16
}) {
	for _, tc := range testCases {
		gotBW, err := connect.FromWireFormat(tc.wireFormat)
		if err != nil {
			t.Fatalf("FromWireFormat(0x%x) failed: %v", tc.wireFormat, err)
		}
		expected := connect.FromKbps(tc.kbps)
		if gotBW != expected {
			t.Errorf("FromWireFormat(0x%x) = %v kbps; want %v kbps",
				tc.wireFormat, gotBW.AsKbps(), expected.AsKbps())
		}
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
		{uint32(1)<<connect.RESID_BITS - 1, true},
		{uint32(1) << connect.RESID_BITS, false},
		{(uint32(1) << connect.RESID_BITS) - 1, true},
		{4194303, true},
		{4194304, false},
	}
	for _, tc := range testCases {
		r := connect.ResInfo{}
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
		{1<<connect.BW_EXP_BITS - 1, true},
		{1 << (connect.BW_EXP_BITS * 8), false},
	}
	for _, tc := range testCases {
		bandwidth := connect.FromKbps(tc.bw)
		wf, err := bandwidth.ToWireFormat()
		if tc.valid != (err == nil) {
			t.Errorf("Bandwidth overflow not handled for %v, got valid %v; want %v",
				tc.bw, err == nil, tc.valid)
		}
		if err != nil {
			_, err = connect.FromWireFormat(1<<16 - 1)
			if err == nil {
				t.Errorf("Bandwidth wireformat overflow not handled for %v,"+
					" got valid %v; want %v", tc.bw, err == nil, tc.valid)
			}
			// Catch invalid BW in Ak computation
			masterKey, _ := base64.StdEncoding.DecodeString(dummy_keys_master0)
			_, err = connect.ComputeAuthenticationKey(connect.ResInfo{
				Bandwidth: connect.FromKbps(tc.bw)},
				([16]byte)(masterKey))
			if err == nil {
				t.Errorf("Bandwidth overflow not handled by ComputeAuthenticationKey for %v,"+
					" got valid %v; want %v", tc.bw, err == nil, tc.valid)
			}
			continue
		}
		// convert back
		bandwidth2, err := connect.FromWireFormat(wf)
		if err != nil {
			t.Errorf("Bandwidth conversion from wire format not handled: %v", err)
		} else if bandwidth != bandwidth2 {
			t.Errorf("Bandwidth conversion from wire format incorrect, got %v; want %v",
				bandwidth2, bandwidth)
		}
	}
	return
}

func TestSampleConfig(t *testing.T) {
	_ = chdirSrvRoot()
	err := setupTestConfig()
	if err != nil {
		t.Fatalf("hummingbird config test setupTestConfig() failed: %v", err)
	}
}

func TestAuthKeyComputation(t *testing.T) {
	_ = chdirSrvRoot()
	path := ".test_config/dummy_keys2"
	masterKey := loadHBMasterSecret(path)

	// Create the service
	svc := connect.NewHummingbirdKeyDerivationService(masterKey)

	// Create a ResInfo
	bw := connect.FromKbps(1200) // 1.2 Mbps
	start := time.Unix(100_000, 0)
	dur := 3600 * time.Second
	isdAs := addr.MustParseIA("1-0000:0000:0110")

	res := connect.NewResInfo(isdAs, 2, 5, bw, start, dur)

	// Check ResInfo
	err := res.Check()
	if err != nil {
		t.Fatalf("res.Check() failed: %v", err)
	}

	// Compute ResID
	res, err = res.WithResID(0x123) // in range for 22 bits
	if err != nil {
		t.Fatalf("res.WithResID(0x123) failed: %v", err)
	}

	// Compute A_k authentication key
	completeReservation, err := svc.AssignAuthenticationKey(res)
	if err != nil {
		t.Fatalf("svc.AssignAuthenticationKey(res) failed: %v", err)
	}

	expectedAk := []byte{0x32, 0x1e, 0xcb, 0x05, 0x69, 0xaf, 0x49, 0x2f, 0x58, 0x4b, 0x59, 0xc6,
		0x60, 0x4f, 0x78, 0xe2}
	fmt.Printf("Derived auth key: %x\n", completeReservation.AuthenticationKey)
	if !slices.Equal(completeReservation.AuthenticationKey, expectedAk) {
		t.Errorf("completeReservation.AuthenticationKey = %v ; want %v ",
			completeReservation.AuthenticationKey, expectedAk)
	}
	var expectedBWP uint64 = 4320000
	if completeReservation.ResInfo.TimeBandwidthProductKb() != expectedBWP {
		t.Errorf("completeReservation.ResInfo.TimeBandwidthProductKb() = %v ; want %v ",
			completeReservation.ResInfo.TimeBandwidthProductKb(), expectedBWP)
	}
}

func TestRedemption(t *testing.T) {
	return
}

func TestClientEncryption(t *testing.T) {
	authenticationKey, err := base64.StdEncoding.DecodeString(testAuthKey)
	if err != nil {
		t.Fatalf("loading Ak failed: %v", err)
	}
	clientKey, err := base64.StdEncoding.DecodeString(testClientPublicKey)
	if err != nil {
		t.Fatalf("loading clientKey failed: %v", err)
	}
	encryptedAk, err := connect.ClientEncrypt(clientKey, authenticationKey)
	if err != nil {
		t.Fatalf("clientEncrypt(Ak) failed: %v", err)
	}
	decryptedAk, err := _clientDecryptTesting(encryptedAk)
	if err != nil {
		t.Fatalf("_clientDecryptTesting failed: %v", err)
	}
	if !bytes.Equal(authenticationKey, decryptedAk) {
		t.Errorf("_clientDecryptTesting(clientEncrypt(Ak)) = %v ; want %v ",
			decryptedAk, authenticationKey)
	}
	return
}

func _clientDecryptTesting(cipher []byte) (plaintext []byte, err error) {
	clientPrivateKey, err := base64.StdEncoding.DecodeString(testClientPrivateKey)
	if err != nil {
		return nil, err
	}
	privKey, err := x509.ParsePKCS1PrivateKey(clientPrivateKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), nil, privKey, cipher, nil)
}

func TestExample(t *testing.T) {
	ExampleHbirdAuthKeyDerivation()
}

func TestLocalServerClientIntegration(t *testing.T) {
	err := chdirSrvRoot()
	if err != nil {
		t.Fatalf("failed to initialize test config dir: %v", err)
	}
	if err := config.LoadFile("./.test_config/hbird.toml", &globalCfg); err != nil {
		fmt.Println(err)
	}
	done := make(chan struct{}, 1)
	var ctx context.Context
	var srvCancel context.CancelFunc
	// Run server
	go func() {
		ctx, srvCancel = context.WithCancel(context.Background())
		err := realMain(ctx)
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("hummingbird service realMain() failed: %v", err)
		}
		fmt.Println("Server canceled.")
		<-done
		fmt.Println("Server terminated.")
		return
	}()
	time.Sleep(2 * time.Second)
	// Client queries here:

	// Status
	fmt.Println("Checking status")
	err = checkStatus()
	if err != nil {
		t.Fatalf("client status request failed: %v", err)
	}

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
				IngressToken: mustDecodeBase64("qL8dQkuHMbFSaQ=="),
				EgressToken:  mustDecodeBase64("LoRzIDXu6k8GjA=="),
			},
		},
		ClientKey: mustDecodeBase64(testClientPublicKey),
	}
	marshaler := protojson.MarshalOptions{UseProtoNames: true}
	jsonRedemptionReq, err := marshaler.Marshal(rreqs)
	if err != nil {
		t.Fatalf("RedemptionRequest encoding failed: %v", err)
	}
	reqBody := bytes.NewBuffer(jsonRedemptionReq)

	if strings.Replace(reqBody.String(), " ", "", -1) != testRedemptionBodyStr {
		t.Fatalf("RedemptionRequest encoding error: got %v;want %v",
			reqBody.String(), testRedemptionBodyStr)
	}

	resp, err := sendRedeem(reqBody.String())
	if err != nil {
		t.Fatalf("client redeem request failed: %v", err)
	}
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
	decryptedAuthKey, err := _clientDecryptTesting(rresp.Reservation[0].AuthKey)
	if err != nil {
		t.Fatalf("RedemptionRequest AuthenticationKey does not decrypt"+
			" under client key: %v", err)
	}
	if base64.StdEncoding.EncodeToString(decryptedAuthKey) != testAuthKey {
		t.Fatalf("RedemptionRequest unexptected AuthenticationKey in response: got %v;want %v",
			resp, testRedemptionResp)
	}
	fmt.Printf("\nDecrypted AuthenticationKey matches expected key\n")
	resInfo := connect.ResInfo{
		IA:               addr.IA(rresp.Reservation[0].GetIa()),
		IngressInterface: uint16(rreqs.Redemption[0].RedInfo.GetIngress()),
		EgressInterface:  uint16(rreqs.Redemption[0].RedInfo.GetEgress()),
		ResID:            rresp.Reservation[0].GetResId(),
		Bandwidth:        connect.FromKbps(uint64(rreqs.Redemption[0].RedInfo.GetBw())),
		StartTime:        time.Unix(int64(rreqs.Redemption[0].RedInfo.GetStartTime()), 0),
		Duration:         mustParseDuration(uint64(rreqs.Redemption[0].RedInfo.GetDuration())),
	}
	masterKey, _ := base64.StdEncoding.DecodeString(dummy_keys_master0)
	recomputedAk, err := checkResInfo(resInfo, ([16]byte)(masterKey))
	if err != nil {
		t.Fatalf("Recomputing auth key for reservation info failed: %v",
			err)
	}
	if !bytes.Equal(recomputedAk[:], decryptedAuthKey) {
		t.Fatalf("RedemptionRequest reservation info does not match auth key: got %v;want %v",
			recomputedAk, decryptedAuthKey)
	}
	fmt.Println("Decrypted AuthenticationKey matches reservation info")

	// Check invalid client key
	rreqs.ClientKey = []byte{0}
	jsonRedemptionReq, err = marshaler.Marshal(rreqs)
	if err != nil {
		t.Fatalf("RedemptionRequest encoding failed: %v", err)
	}
	reqBody = bytes.NewBuffer(jsonRedemptionReq)
	resp, err = sendRedeem(reqBody.String())
	if err == nil {
		t.Fatalf("client redeem succeeded with invalid client key: %v", err)
	}

	// Check not implemented
	fmt.Printf("\nChecking not implemented\n")
	err = checkNotImplementedProcedure()
	if err == nil || !strings.HasSuffix(err.Error(), fmt.Sprint(http.StatusNotFound)) {
		t.Fatalf("Client request to missing procedure did not return "+
			"expected error : %v; want %v", err, http.StatusNotFound)
	}
	fmt.Printf("\nChecking wrong endpoint\n")
	err = checkNotImplementedEndpoint()
	if err == nil || !strings.HasSuffix(err.Error(), fmt.Sprint(http.StatusNotFound)) {
		t.Fatalf("Client request to missing endpoint did not return "+
			"expected error : %v; want %v", err, http.StatusNotFound)
	}

	// Send cancel to server
	srvCancel()
	fmt.Printf("\nTerminating server.\n")
	// Terminate server
	done <- struct{}{}
	fmt.Println("Sent server shutdown signal.")
	time.Sleep(2 * time.Second)
	// Check status against shutdown server
	fmt.Printf("\nChecking against shutdown server\n")
	err = checkStatus()
	var urlError *url.Error
	var syscallError *os.SyscallError
	if !(err != nil && errors.As(err, &urlError) &&
		errors.As(err, &syscallError) && syscallError.Err == syscall.ECONNREFUSED) {
		t.Fatalf("Client request to shudown server did not return "+
			"expected error : %v; want %v", syscallError.Err, syscall.ECONNREFUSED)
	}
	fmt.Printf("Got expected connection error\n\n")
	fmt.Println("TestServerClientIntegration completed")
	return
}

func checkStatus() error {
	requestURL := fmt.Sprintf("http://localhost:%d%s",
		serverPort, hbirdv1connect.HBirdServiceStatusProcedure)
	bodyStr := `{}`
	_, err := query(requestURL, bodyStr, false)
	return err
}

func checkNotImplementedProcedure() error {
	requestURL := fmt.Sprintf("http://localhost:%d%s2",
		serverPort, hbirdv1connect.HBirdServiceStatusProcedure)
	bodyStr := `{}`
	_, err := query(requestURL, bodyStr, false)
	return err
}

func checkNotImplementedEndpoint() error {
	requestURL := fmt.Sprintf("http://localhost:%d/Status", serverPort)
	bodyStr := `{}`
	_, err := query(requestURL, bodyStr, false)
	return err
}

func checkResInfo(resInfo connect.ResInfo, masterKey [16]byte) (*[16]byte, error) {
	return connect.ComputeAuthenticationKey(resInfo, masterKey)
}

func sendRedeem(redeemBody string) ([]byte, error) {
	requestURL := fmt.Sprintf("http://localhost:%d%s",
		serverPort, hbirdv1connect.HBirdServiceRedeemProcedure)
	bodyStr := redeemBody
	return query(requestURL, bodyStr, true)
}

func query(requestURL, bodyStr string, checkResponse bool) ([]byte, error) {
	res, err := makeHTTPRequest(requestURL, bodyStr)
	if err != nil {
		return nil, err
	}
	pathSegments := strings.Split(requestURL, "/")
	procedureName := pathSegments[len(pathSegments)-1]
	fmt.Printf("%s response status: %d\n", procedureName, res.StatusCode)
	if res.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("wrong status code: %d", res.StatusCode))
	}
	response, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	fmt.Printf("%s response: %s\n", procedureName, response)
	return response, nil
}

func makeHTTPRequest(requestURL, bodyStr string) (*http.Response, error) {
	var b bytes.Buffer
	b.WriteString(bodyStr)
	return http.Post(requestURL, "application/json", bytes.NewReader(b.Bytes()))
}

func mustDecodeBase64(s string) []byte {
	var b []byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustParseDuration(i uint64) time.Duration {
	duration, err := time.ParseDuration(fmt.Sprintf("%ds", i))
	if err != nil {
		panic(err)
	}
	return duration
}

func setupTestConfig() error {
	currentDir, _ := os.Getwd()
	testConfigDir := filepath.Join(currentDir, ".test_config")
	if _, err := os.Stat(testConfigDir); err != nil {
		err = os.Mkdir(testConfigDir, 0744)
		if err != nil {
			return err
		}
	}

	files := map[string](func(string, string) error){
		"hbird.toml":              writeHbird,
		"topology.json":           writeTopo,
		"dummy_keys/master0.key":  writeDummyKey,
		"dummy_keys/master1.key":  writeDummyKey,
		"dummy_keys2/master0.key": writeDummyKey2,
		"dummy_keys2/master1.key": writeDummyKey2,
	}
	for name, wFun := range files {
		path := filepath.Join(testConfigDir, name)
		if _, err := os.Stat(path); err != nil {
			err = wFun(path, testConfigDir)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func writeHbird(path, testConfigDir string) error {
	cfg, err := generateHBSampleConfig()
	if err != nil {
		return err
	}
	// update config for tests
	cfg.Logging.Console.Level = "debug"
	cfg.General.ConfigDir = testConfigDir

	// write out HB config
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var sample bytes.Buffer
	err = toml.NewEncoder(&sample).Encode(cfg)
	if err != nil {
		return err
	}
	_, err = f.Write(sample.Bytes())
	return err
}

func writeTopo(path, _ string) error {
	// write out topo file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var b bytes.Buffer
	b.WriteString(sampleTopology)
	_, err = f.Write(b.Bytes())
	return err
}

func writeDummyKey(path, testConfigDir string) error {
	dummyKeysDir := filepath.Join(testConfigDir, "dummy_keys")
	var payload string
	if strings.HasSuffix(path, "master0.key") {
		payload = dummy_keys_master0
	}
	if strings.HasSuffix(path, "master1.key") {
		payload = dummy_keys_master1
	}
	return writeDummyKeys(path, dummyKeysDir, payload)
}

func writeDummyKey2(path, testConfigDir string) error {
	dummyKeysDir := filepath.Join(testConfigDir, "dummy_keys2")
	var payload string
	if strings.HasSuffix(path, "master0.key") {
		payload = dummy_keys2_master0
	}
	if strings.HasSuffix(path, "master1.key") {
		payload = dummy_keys2_master1
	}
	return writeDummyKeys(path, dummyKeysDir, payload)
}

func writeDummyKeys(path, dummyKeysDir, payload string) error {
	if _, err := os.Stat(dummyKeysDir); err != nil {
		err = os.Mkdir(dummyKeysDir, 0744)
		if err != nil {
			return err
		}
	}
	// write out dummy key
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var b bytes.Buffer
	b.WriteString(payload)
	_, err = f.Write(b.Bytes())

	return err
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

func chdirSrvRoot() error {
	currentDir, _ := os.Getwd()
	if !strings.HasSuffix(currentDir, "/hbird") || strings.Contains(currentDir, "/cmd/hummingbird") {
		err := os.Chdir(filepath.Dir(filepath.Dir(currentDir)))
		if err != nil {
			return err
		}
		currentDir, err = os.Getwd()
		if err != nil {
			return err
		}
		if _, err = os.Stat(currentDir); err != nil {
			return err
		}
	}
	return nil
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
