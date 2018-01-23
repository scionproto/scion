// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !go1.9

// This version of sockctrl is for Go versions < 1.9, where the socket FDs are
// inaccessible without reflection.
package sockctrl

import (
	"fmt"
	"net"
	"reflect"

	"github.com/scionproto/scion/go/lib/common"
)

func SockControl(c *net.UDPConn, f func(int) error) error {
	fd, err := socketOf(c)
	if err != nil {
		return common.NewBasicError("sockctrl: unable to get socket fd", err)
	}
	return f(int(fd))
}

// From https://github.com/golang/net/blob/e1564c30db987d37eab1a340b7a2e4d2f71f7430/internal/socket/reflect.go
func socketOf(c net.Conn) (uintptr, error) {
	switch c.(type) {
	case *net.TCPConn, *net.UDPConn, *net.IPConn:
		v := reflect.ValueOf(c)
		switch e := v.Elem(); e.Kind() {
		case reflect.Struct:
			fd := e.FieldByName("conn").FieldByName("fd")
			switch e := fd.Elem(); e.Kind() {
			case reflect.Struct:
				sysfd := e.FieldByName("sysfd")
				return uintptr(sysfd.Int()), nil
			}
		}
	}
	return 0, fmt.Errorf("invalid type: %s", common.TypeOf(c))
}
