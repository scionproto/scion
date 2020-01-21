package snet_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestUDPAddrInterface(t *testing.T) {
	var x interface{} = &snet.UDPAddr{}
	_, ok := x.(net.Addr)
	assert.True(t, ok, "should implement net interface")
}

func TestUDPAddrString(t *testing.T) {
	tests := map[string]struct {
		input *snet.UDPAddr
		want  string
	}{
		"empty": {
			input: &snet.UDPAddr{},
			want:  "0-0,[<nil>]:0",
		},
		"empty host": {
			input: &snet.UDPAddr{Host: &net.UDPAddr{}},
			want:  "0-0,[<nil>]:0",
		},
	}
	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			a := tc.input.String()
			assert.Equal(t, a, tc.want)
		})
	}
}

func TestUDPAddrSet(t *testing.T) {
	testCases := map[string]struct {
		Input string
		Error assert.ErrorAssertionFunc
		Want  *snet.UDPAddr
	}{
		"empty string": {
			Input: "",
			Error: assert.Error,
		},
		"malformed IA": {
			Input: "1-ff000:0:0,[192.168.1.1]:80",
			Error: assert.Error,
		},
		"malformed IP": {
			Input: "1-ff00:0:1,[192.1688.1.1]:80",
			Error: assert.Error,
		},
		"malformed port": {
			Input: "1-ff00:0:1,[192.168.1.1]:123456",
			Error: assert.Error,
		},
		"bad symbol": {
			Input: "1-ff00:0:1x[192.168.1.1]:80",
			Error: assert.Error,
		},
		"good input": {
			Input: "1-ff00:0:1,[192.168.1.1]:80",
			Error: assert.NoError,
			Want: snet.NewUDPAddr(
				xtest.MustParseIA("1-ff00:0:1"),
				nil,
				nil,
				&net.UDPAddr{
					IP:   net.IP{192, 168, 1, 1},
					Port: 80,
				},
			),
		},
	}
	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {
			var a snet.UDPAddr
			err := a.Set(tc.Input)
			tc.Error(t, err)
			if err == nil {
				assert.Equal(t, tc.Want, &a)
			}
		})
	}
}
