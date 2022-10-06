// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

package xtest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"

	"github.com/scionproto/scion/pkg/addr"
)

// Update registers the '-update' flag for the test.
//
// This flag should be checked by golden file tests to see whether the golden
// files should be updated or not. The golden files should be deterministic.
// Use UpdateNonDeterminsticGoldenFiles instead, if they are not deterministic.
//
// To update all golden files, run the following command:
//
//	go test ./... -update
//
// To update a specific package, run the following command:
//
//	go test ./path/to/package -update
//
// The flag should be registered as a package global variable:
//
//	var update = xtest.UpdateGoldenFiles()
func UpdateGoldenFiles() *bool {
	return flag.Bool("update", false, "set to regenerate the golden files")
}

// UpdateNonDeterminsticGoldenFiles registers the '-update-non-deterministic'
// flag for the test.
//
// This flag should be checked by golden file tests to see whether the
// non-deterministic golden files should be updated or not.
//
// To update all golden files, run the following command:
//
//	go test ./... -update-non-deterministic
//
// To update a specific package, run the following command:
//
//	go test ./path/to/package -update-non-deterministic
//
// The flag should be registered as a package global variable:
//
//	var updateNonDeterministic = xtest.UpdateNonDeterminsticGoldenFiles()
func UpdateNonDeterminsticGoldenFiles() *bool {
	return flag.Bool("update-non-deterministic", false,
		"set to regenerate the non-deterministic golden files",
	)
}

// TempFileName creates a temporary file in dir with the specified prefix, and
// then closes and deletes the file and returns its name. It is useful for
// testing packages that care about a unique path without being able to
// overwrite it (e.g., UNIX domain socket addresses or databases).
func TempFileName(dir, prefix string) (string, error) {
	file, err := os.CreateTemp(dir, prefix)
	if err != nil {
		return "", err
	}

	name := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}

	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

// MustTempFileName is a wrapper around TempFileName. The function panics if an
// error occurs. It is intended for tests where error handling is not
// necessary, and for chaining functions.
func MustTempFileName(dir, prefix string) string {
	name, err := TempFileName(dir, prefix)
	if err != nil {
		panic(err)
	}
	return name
}

// MustTempDir creates a new temporary directory under dir with the specified
// prefix. If the function encounters an error it panics. The second return
// value is a clean-up function that can be called to recursively delete the
// entire directory.
func MustTempDir(dir, prefix string) (string, func()) {
	name, err := os.MkdirTemp(dir, prefix)
	if err != nil {
		panic(err)
	}
	return name, func() {
		os.RemoveAll(name)
	}
}

// SanitizedName sanitizes the test name such that it can be used as a file name.
func SanitizedName(t testing.TB) string {
	return strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_").Replace(t.Name())
}

func TempDir(t testing.TB) (string, func()) {
	name, err := os.MkdirTemp("", fmt.Sprintf("%s_*", SanitizedName(t)))
	require.NoError(t, err)
	return name, func() {
		os.RemoveAll(name)
	}
}

// CopyDir copies "from" to "to", using the unix cp command.
func CopyDir(t testing.TB, from, to string) {
	t.Helper()
	cmd := exec.Command("cp", "-rL", from, to)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// CopyFile copies the file.
func CopyFile(t testing.TB, src, dst string) {
	t.Helper()

	raw, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, raw, 0666))
}

// FailOnErr causes t to exit with a fatal error if err is non-nil.
func FailOnErr(t testing.TB, err error, desc ...string) {
	t.Helper()

	if err != nil {
		t.Fatal(strings.Join(desc, " "), err)
	}
}

// MustMarshalJSONToFile marshals v and writes the result to file
// testdata/baseName. If the file exists, it is truncated; if it doesn't exist,
// it is created. On errors, t.Fatal() is called.
func MustMarshalJSONToFile(t testing.TB, v interface{}, baseName string) {
	t.Helper()

	enc, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		t.Fatal(err)
	}

	buffer := bytes.NewBuffer(enc)
	if err := buffer.WriteByte('\n'); err != nil {
		t.Fatal(err)
	}

	MustWriteToFile(t, buffer.Bytes(), baseName)
}

// MustWriteToFile writes b to file testdata/baseName. If the file exists, it
// is truncated; if it doesn't exist, it is created. On errors, t.Fatal() is
// called.
func MustWriteToFile(t testing.TB, b []byte, baseName string) {
	t.Helper()

	if err := os.WriteFile(ExpandPath(baseName), b, 0644); err != nil {
		t.Fatal(err)
	}
}

// MustReadFromFile reads testdata/baseName and returns the raw content. On
// errors, t.Fatal() is called.
func MustReadFromFile(t testing.TB, baseName string) []byte {
	t.Helper()

	name := filepath.Join("testdata", baseName)
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ExpandPath returns testdata/file.
func ExpandPath(file string) string {
	return filepath.Join("testdata", file)
}

// MustParseIA parses s and returns the corresponding addr.IA object. It
// panics if s is not a valid ISD-AS representation.
func MustParseIA(s string) addr.IA {
	ia, err := addr.ParseIA(s)
	if err != nil {
		panic(err)
	}
	return ia
}

// MustParseIAs parses a list of comma separated ISD-AS strings. It panics in case
// parsing fails.
func MustParseIAs(list string) []addr.IA {
	l := strings.Split(list, ",")
	var ias []addr.IA
	for _, raw := range l {
		ias = append(ias, MustParseIA(raw))
	}
	return ias
}

// MustParseAS parses s and returns the corresponding addr.AS object. It panics
// if s is not valid AS representation.
func MustParseAS(s string) addr.AS {
	ia, err := addr.ParseAS(s)
	if err != nil {
		panic(err)
	}
	return ia
}

// MustParseASes parses a list of comma separated AS strings. It panics in case
// parsing fails.
func MustParseASes(list string) []addr.AS {
	l := strings.Split(list, ",")
	var ases []addr.AS
	for _, raw := range l {
		ases = append(ases, MustParseAS(raw))
	}
	return ases
}

// MustParseHexString parses s and returns the corresponding byte slice.
// It panics if the decoding fails.
func MustParseHexString(s string) []byte {
	// remove whitespace
	reg, err := regexp.Compile(`\s+`)
	if err != nil {
		panic(err)
	}
	s = reg.ReplaceAllString(s, "")

	decoded, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return decoded
}

// MustParseCIDR parses s and returns the corresponding net.IPNet object. It
// fails the test if s is not a valid CIDR string.
func MustParseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(s)
	require.NoError(t, err)
	return network
}

// MustParseCIDRs parses the CIDR entries and returns a list containing the
// parsed net.IPNet objects.
func MustParseCIDRs(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()

	result := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		result = append(result, MustParseCIDR(t, e))
	}
	return result
}

// MustParseIPPrefixes parses the CIDR entries and returns a list containing the
// parsed netaddr.IPPrefix objects.
func MustParseIPPrefixes(t *testing.T, prefixes ...string) []netaddr.IPPrefix {
	t.Helper()
	var result []netaddr.IPPrefix
	for _, prefix := range prefixes {
		p, err := netaddr.ParseIPPrefix(prefix)
		require.NoError(t, err)
		result = append(result, p)
	}
	return result
}

// MustParseIP parses an IP address and returns the parsed net.IP object.
func MustParseIP(t *testing.T, addr string) net.IP {
	t.Helper()

	ip := net.ParseIP(addr)
	require.NotNil(t, ip)
	return ip
}

// MustParseUDPAddr parses s and returns the corresponding net.UDPAddr object.
// It fails the test if s is not a valid UDP address string.
func MustParseUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()

	a, err := net.ResolveUDPAddr("udp", s)
	require.NoError(t, err)
	if ipv4 := a.IP.To4(); ipv4 != nil {
		a.IP = ipv4
	}
	return a
}

// MustParseUDPAddrs parses the UPD address entries and returns a list
// containing the parsed net.UDPAddr objects.
func MustParseUDPAddrs(t *testing.T, entries ...string) []*net.UDPAddr {
	t.Helper()

	result := make([]*net.UDPAddr, 0, len(entries))
	for _, e := range entries {
		result = append(result, MustParseUDPAddr(t, e))
	}
	return result
}

// AssertReadReturnsBetween will call t.Fatalf if the first read from the
// channel doesn't happen between x and y.
func AssertReadReturnsBetween(t testing.TB, ch <-chan struct{}, x, y time.Duration) {
	AssertReadDoesNotReturnBefore(t, ch, x)
	// Above aborts the test if it returns before x time passed, so if we get
	// here x time has passed.
	AssertReadReturnsBefore(t, ch, y-x)
}

// AssertReadReturnsBefore will call t.Fatalf if the first read from the
// channel doesn't happen before timeout.
func AssertReadReturnsBefore(t testing.TB, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("goroutine took too long to finish")
	}
}

// AssertReadDoesNotReturnBefore will call t.Fatalf if the first read from the
// channel happens before timeout.
func AssertReadDoesNotReturnBefore(t testing.TB, ch <-chan struct{}, timeout time.Duration) {
	select {
	case <-ch:
		t.Fatalf("goroutine finished too quickly")
	case <-time.After(timeout):
	}
}

// AssertError checks that err is not nil if expectError is true and that is it nil otherwise
func AssertError(t *testing.T, err error, expectError bool) {
	if expectError {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}
