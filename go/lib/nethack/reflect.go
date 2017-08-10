// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !go1.9
// FIXME(kormat): this is only needed until we switch to go1.9, which will
// grant access to the file descriptor underlying net.Conn.

package nethack

import (
	"errors"
	"net"
	"reflect"
)

// From https://github.com/golang/net/blob/e1564c30db987d37eab1a340b7a2e4d2f71f7430/internal/socket/reflect.go
func SocketOf(c net.Conn) (int, error) {
	switch c.(type) {
	case *net.TCPConn, *net.UDPConn, *net.IPConn:
		v := reflect.ValueOf(c)
		switch e := v.Elem(); e.Kind() {
		case reflect.Struct:
			fd := e.FieldByName("conn").FieldByName("fd")
			switch e := fd.Elem(); e.Kind() {
			case reflect.Struct:
				sysfd := e.FieldByName("sysfd")
				return int(sysfd.Int()), nil
			}
		}
	}
	return 0, errors.New("invalid type")
}
