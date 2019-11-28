package snet_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/snet"
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
