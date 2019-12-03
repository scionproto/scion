package snet_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/snet"
)

func TestSVCAddrInterface(t *testing.T) {
	var x interface{} = &snet.SVCAddr{}
	_, ok := x.(net.Addr)
	assert.True(t, ok, "should implement net interface")
}

func TestSVCAddrString(t *testing.T) {
	tests := map[string]struct {
		input *snet.SVCAddr
		want  string
	}{
		"nil": {
			input: &snet.SVCAddr{},
			want:  "0-0,BS A (0x0000)",
		},
	}
	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			a := tc.input.String()
			assert.Equal(t, a, tc.want)
		})
	}
}
