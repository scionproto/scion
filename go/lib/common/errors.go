// Copyright 2016 ETH Zurich
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

package common

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/assert"
)

// ErrorMsger allows extracting the message from an error. This means a caller
// can determine the type of error by comparing the returned message with a
// const error string. E.g.:
// if GetErrorMsg(err) == addr.ErrorBadHostAddrType {
//    // Handle bad host addr error
// }
type ErrorMsger interface {
	error
	GetMsg() string
}

// GetErrorMsg extracts the message from e, if e implements the ErrorMsger
// interface. As a fall-back, if e implements ErrorNester, GetErrorMsg recurses on
// the nested error. Otherwise returns an empty string.
func GetErrorMsg(e error) string {
	if e, _ := e.(ErrorMsger); e != nil {
		return e.GetMsg()
	}
	if n := GetNestedError(e); n != nil {
		return GetErrorMsg(n)
	}
	return ""
}

// ErrorNester allows recursing into nested errors.
type ErrorNester interface {
	error
	GetErr() error
}

// GetNestedError returns the nested error, if any. Returns nil otherwise.
func GetNestedError(e error) error {
	if n, _ := e.(ErrorNester); n != nil {
		return n.GetErr()
	}
	return nil
}

// Temporary allows signalling of a temporary error. Based on https://golang.org/pkg/net/#Error
type Temporary interface {
	error
	Temporary() bool
}

// IsTemporaryErr determins if e is a temporary Error. As a fall-back, if e implements ErrorNester,
// IsTemporaryErr recurses on the nested error. Otherwise returns false.
func IsTemporaryErr(e error) bool {
	if t, _ := e.(Temporary); t != nil {
		return t.Temporary()
	}
	if n := GetNestedError(e); n != nil {
		return IsTemporaryErr(n)
	}
	return false
}

// Temporary allows signalling of a timeout error. Based on https://golang.org/pkg/net/#Error
type Timeout interface {
	error
	Timeout() bool
}

// IsTimeoutErr determins if e is a temporary Error. As a fall-back, if e implements ErrorNester,
// IsTimeoutErr recurses on the nested error. Otherwise returns false.
func IsTimeoutErr(e error) bool {
	if t, _ := e.(Timeout); t != nil {
		return t.Timeout()
	}
	if n := GetNestedError(e); n != nil {
		return IsTimeoutErr(n)
	}
	return false
}

var _ ErrorMsger = BasicError{}
var _ ErrorNester = BasicError{}

// BasicError is a simple error type that implements ErrorMsger and ErrorNester,
// and can contain context (slice of [string, val, string, val...]) for logging purposes.
type BasicError struct {
	// Error message
	Msg string
	// Error context, for logging purposes only
	logCtx []interface{}
	// Nested error, if any.
	Err error
}

// NewBasicError creates a new BasicError, with e as the embedded error (can be nil), with logCtx
// being a list of string/val pairs.
func NewBasicError(msg string, e error, logCtx ...interface{}) error {
	if assert.On {
		assert.Must(len(logCtx)%2 == 0, "Log context must have an even number of elements")
		for i := 0; i < len(logCtx); i += 2 {
			_, ok := logCtx[i].(string)
			assert.Must(ok, "First element of each log context pair must be a string")
		}
	}
	return BasicError{Msg: msg, logCtx: logCtx, Err: e}
}

func (be BasicError) Error() string {
	s := make([]string, 0, 1+(len(be.logCtx)/2))
	s = append(s, be.Msg)
	s[0] = be.Msg
	for i := 0; i < len(be.logCtx); i += 2 {
		s = append(s, fmt.Sprintf("%s=\"%v\"", be.logCtx[i], be.logCtx[i+1]))
	}
	return strings.Join(s, " ")
}

func (be BasicError) GetMsg() string {
	return be.Msg
}

func (be BasicError) GetErr() error {
	return be.Err
}

// FmtError formats e for logging. It walks through all nested errors, putting each on a new line,
// and indenting multi-line errors.
func FmtError(e error) string {
	var s, ns []string
	for {
		ns, e = innerFmtError(e)
		s = append(s, ns...)
		if e == nil {
			break
		}
	}
	return strings.Join(s, "\n    ")
}

func innerFmtError(e error) ([]string, error) {
	var s []string
	lines := strings.Split(e.Error(), "\n")
	for i, line := range lines {
		if i == len(lines)-1 && len(line) == 0 {
			// Don't output an empty line if caused by a trailing newline in
			// the input.
			break
		}
		if i == 0 {
			s = append(s, line)
		} else {
			s = append(s, ">   "+line)
		}
	}
	return s, GetNestedError(e)
}
