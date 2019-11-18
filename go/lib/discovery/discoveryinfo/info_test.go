package discoveryinfo

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	cases := map[string]struct {
		key  string
		addr *net.UDPAddr
	}{
		"empty address": {key: "x", addr: &net.UDPAddr{}},
	}

	for n, tc := range cases {
		t.Run(n, func(t *testing.T) {
			got := New(tc.key, tc.addr)
			assert.NotNil(t, got)
		})
	}
}

func TestUpdate(t *testing.T) {
	cases := map[string]struct {
		before, after *Info
		input         *net.UDPAddr
	}{
		"nil addr": {
			before: &Info{
				addr:      &net.UDPAddr{},
				failCount: 10,
			},
			input: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			after: &Info{
				addr:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
				failCount: 0,
			},
		},
		"not nil addr": {
			before: &Info{
				addr:      &net.UDPAddr{IP: net.ParseIP("127.0.0.10"), Port: 1234},
				failCount: 10,
			},
			input: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			after: &Info{
				addr:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
				failCount: 0,
			},
		},
		"same addr": {
			before: &Info{
				addr:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
				failCount: 10,
			},
			input: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			after: &Info{
				addr:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
				failCount: 10,
			},
		},
	}

	for n, tc := range cases {
		t.Run(n, func(t *testing.T) {
			tc.before.Update(tc.input)
			tc.input.IP[0] = 42 // other part of the code modifies the input reference.
			assert.Equal(t, tc.before.addr, tc.after.addr)
			assert.Equal(t, tc.before.failCount, tc.after.failCount)
		})
	}
}

func TestAddr(t *testing.T) {
	cases := map[string]struct {
		before *Info
		want   *net.UDPAddr
	}{
		"addr": {
			before: &Info{
				addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			},
			want: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
		},
	}

	for n, tc := range cases {
		t.Run(n, func(t *testing.T) {
			got := tc.before.Addr()
			tc.before.addr.IP[0] = 42 // other part of the code modifies the IP reference.
			assert.Equal(t, got, tc.want)
		})
	}
}
