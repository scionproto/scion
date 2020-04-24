// Copyright 2019 Anapaya Systems

package fake_test

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/fake"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
)

var update = flag.Bool("update", false, "set to true to update golden files")

func TestJSONConversion(t *testing.T) {
	script := &fake.Script{
		Entries: []*fake.Entry{
			{
				ReplyStartTimestamp: 0,
				Paths: []*fake.Path{
					{
						JSONFingerprint: "Foo",
						JSONNextHop: &fake.UDPAddr{
							IP:   net.IP{192, 168, 0, 1},
							Port: 80,
						},
						JSONIA:                  xtest.MustParseIA("1-ff00:0:1"),
						JSONExpirationTimestamp: 7200,
					},
				},
			},
		},
	}

	bytes, err := json.MarshalIndent(script, "  ", "  ")
	require.NoError(t, err)
	bytes = append(bytes, '\n')
	if *update {
		err = ioutil.WriteFile("testdata/sd.json", bytes, 0644)
		require.NoError(t, err)
	}

	loadedBytes, err := ioutil.ReadFile("testdata/sd.json")
	require.NoError(t, err)
	assert.Equal(t, bytes, loadedBytes)

	var loadedScript fake.Script
	err = json.Unmarshal(loadedBytes, &loadedScript)
	require.NoError(t, err)

	assert.Equal(t, script, &loadedScript)
}

func TestPaths(t *testing.T) {
	script := &fake.Script{
		Entries: []*fake.Entry{
			{
				ReplyStartTimestamp: 0,
				Paths: []*fake.Path{
					{
						JSONFingerprint: "Foo",
						JSONNextHop: &fake.UDPAddr{
							IP:   net.IP{10, 0, 0, 1},
							Port: 80,
						},
						JSONIA:                  xtest.MustParseIA("1-ff00:0:1"),
						JSONExpirationTimestamp: 7200,
					},
				},
			},
			{
				ReplyStartTimestamp: 1,
				Paths: []*fake.Path{
					{
						JSONFingerprint: "Foo2",
						JSONNextHop: &fake.UDPAddr{
							IP:   net.IP{10, 0, 0, 2},
							Port: 80,
						},
						JSONIA:                  xtest.MustParseIA("2-ff00:0:2"),
						JSONExpirationTimestamp: 10800,
					},
				},
			},
		},
	}
	c := fake.New(script)

	paths, err := c.Paths(
		context.Background(),
		xtest.MustParseIA("1-ff00:0:1"),
		xtest.MustParseIA("1-ff00:0:2"),
		sciond.PathReqFlags{PathCount: 5},
	)
	require.NoError(t, err)

	require.Equal(t, 1, len(paths))
	assert.Equal(t, "Foo", string(paths[0].Fingerprint()))
	assert.Equal(t, &net.UDPAddr{IP: net.IP{10, 0, 0, 1}, Port: 80}, paths[0].UnderlayNextHop())
	assert.Equal(t, fake.DummyPath(), paths[0].Path())
	assert.Equal(t, []snet.PathInterface{}, paths[0].Interfaces())
	assert.Equal(t, xtest.MustParseIA("1-ff00:0:1"), paths[0].Destination())
	assert.Equal(t, uint16(1472), paths[0].MTU())
	// path valid for more than an hour, but less than three
	assert.True(t, paths[0].Expiry().After(time.Now().Add(time.Hour)))
	assert.True(t, paths[0].Expiry().Before(time.Now().Add(3*time.Hour)))

	time.Sleep(time.Second)

	paths, err = c.Paths(
		context.Background(),
		xtest.MustParseIA("1-ff00:0:1"),
		xtest.MustParseIA("1-ff00:0:2"),
		sciond.PathReqFlags{PathCount: 5},
	)
	require.NoError(t, err)

	require.Equal(t, 1, len(paths))
	assert.Equal(t, "Foo2", string(paths[0].Fingerprint()))
	assert.Equal(t, &net.UDPAddr{IP: net.IP{10, 0, 0, 2}, Port: 80}, paths[0].UnderlayNextHop())
	assert.Equal(t, fake.DummyPath(), paths[0].Path())
	assert.Equal(t, []snet.PathInterface{}, paths[0].Interfaces())
	assert.Equal(t, xtest.MustParseIA("2-ff00:0:2"), paths[0].Destination())
	assert.Equal(t, uint16(1472), paths[0].MTU())
	// path valid for more than two hours, but less than four
	assert.True(t, paths[0].Expiry().After(time.Now().Add(2*time.Hour)))
	assert.True(t, paths[0].Expiry().Before(time.Now().Add(4*time.Hour)))
}

func TestPathCopy(t *testing.T) {
	path := fake.Path{
		JSONFingerprint: "foo",
		JSONNextHop: &fake.UDPAddr{
			IP:   net.IP{192, 168, 0, 1},
			Port: 80,
			Zone: "abc",
		},
		JSONIA: xtest.MustParseIA("1-ff00:0:1"),
	}

	copyPath := path.Copy()
	assert.Equal(t, &path, copyPath.(*fake.Path))

	path.JSONNextHop.Port = 8080
	path.JSONNextHop.IP[3] = 1

	assert.Equal(t, 80, copyPath.(*fake.Path).JSONNextHop.Port)
	assert.Equal(t, net.IP{192, 168, 0, 1}, copyPath.(*fake.Path).JSONNextHop.IP)
}

func TestASInfo(t *testing.T) {
	c := fake.New(&fake.Script{})
	assert.PanicsWithValue(t, "not implemented", func() { c.ASInfo(nil, addr.IA{}) })
}

func TestIFInfo(t *testing.T) {
	c := fake.New(&fake.Script{})
	assert.PanicsWithValue(t, "not implemented", func() { c.IFInfo(nil, nil) })
}

func TestSVCInfo(t *testing.T) {
	c := fake.New(&fake.Script{})
	assert.PanicsWithValue(t, "not implemented", func() { c.SVCInfo(nil, nil) })

}

func TestRevNotificationFromRaw(t *testing.T) {
	c := fake.New(&fake.Script{})
	assert.PanicsWithValue(t, "not implemented", func() { c.RevNotificationFromRaw(nil, nil) })
}

func TestRevNotification(t *testing.T) {
	c := fake.New(&fake.Script{})
	assert.PanicsWithValue(t, "not implemented", func() { c.RevNotification(nil, nil) })
}

func TestClose(t *testing.T) {
	c := fake.New(&fake.Script{})
	assert.NoError(t, c.Close(nil))
}

func TestUDPAddrMarshalText(t *testing.T) {
	testCases := []struct {
		Name         string
		InputAddress *fake.UDPAddr
		OutputText   []byte
	}{
		{
			Name: "ipv4",
			InputAddress: &fake.UDPAddr{
				IP:   net.IP{10, 0, 0, 1},
				Port: 80,
			},
			OutputText: []byte("10.0.0.1:80"),
		},
		{
			Name: "ipv6",
			InputAddress: &fake.UDPAddr{
				IP:   net.IPv6loopback,
				Port: 80,
			},
			OutputText: []byte("[::1]:80"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			outputText, err := tc.InputAddress.MarshalText()
			assert.NoError(t, err)
			assert.Equal(t, tc.OutputText, outputText)
		})
	}
}

func TestUDPAddrUnmarshalText(t *testing.T) {
	testCases := []struct {
		Name          string
		InputText     []byte
		OutputAddress fake.UDPAddr
		OutputError   assert.ErrorAssertionFunc
	}{
		{
			Name:      "ipv4",
			InputText: []byte("10.0.0.1:80"),
			OutputAddress: fake.UDPAddr{
				IP:   net.IP{10, 0, 0, 1},
				Port: 80,
			},
			OutputError: assert.NoError,
		},
		{
			Name:      "ipv6",
			InputText: []byte("[::1]:80"),
			OutputAddress: fake.UDPAddr{
				IP:   net.IPv6loopback,
				Port: 80,
			},
			OutputError: assert.NoError,
		},
		{
			Name:        "parse error",
			InputText:   []byte("foo"),
			OutputError: assert.Error,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var outputAddress fake.UDPAddr
			err := outputAddress.UnmarshalText(tc.InputText)
			tc.OutputError(t, err)
			assert.Equal(t, tc.OutputAddress, outputAddress)
		})
	}
}
