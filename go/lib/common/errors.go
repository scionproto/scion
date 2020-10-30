// Copyright 2016 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

// ErrorNester allows recursing into nested errors.
type ErrorNester interface {
	error
	TopError() string // should not include the nested error
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

// IsTemporaryErr determines if e is a temporary Error. As a fall-back, if e implements ErrorNester,
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

// Timeout allows signalling of a timeout error. Based on https://golang.org/pkg/net/#Error
type Timeout interface {
	error
	Timeout() bool
}

// IsTimeoutErr determines if e is a temporary Error. As a fall-back, if e implements ErrorNester,
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

// ErrMsg should be used for error string constants. The constant can then be
// used for Is checking in the calling code.
type ErrMsg string

func (e ErrMsg) Error() string {
	return string(e)
}

var _ ErrorMsger = BasicError{}
var _ ErrorNester = BasicError{}

// BasicError is a simple error type that implements ErrorMsger and ErrorNester,
// and can contain context (slice of [string, val, string, val...]) for logging purposes.
type BasicError struct {
	// Error message
	Msg ErrMsg
	// Error context, for logging purposes only
	logCtx []interface{}
	// Nested error, if any.
	Err error
}

// Is returns whether this error is the same error as err, or in case err is a
// ErrMsg whether the message is equal.
func (be BasicError) Is(err error) bool {
	switch other := err.(type) {
	case BasicError:
		return be.Msg == other.Msg
	case ErrMsg:
		return be.Msg == other
	default:
		return false
	}
}

// Unwrap returns the next error in the error chain, or nil if there is none.
func (be BasicError) Unwrap() error {
	return be.GetErr()
}

// NewBasicError creates a new BasicError, with e as the embedded error (can be nil), with logCtx
// being a list of string/val pairs. These key/value pairs should contain all context-dependent
// information: 'msg' argument itself should be a constant string.
func NewBasicError(msg ErrMsg, e error, logCtx ...interface{}) error {
	return BasicError{Msg: msg, logCtx: logCtx, Err: e}
}

func (be BasicError) TopError() string {
	s := make([]string, 0, 1+(len(be.logCtx)/2))
	s = append(s, string(be.Msg))
	s[0] = string(be.Msg)
	for i := 0; i < len(be.logCtx); i += 2 {
		s = append(s, fmt.Sprintf("%s=\"%v\"", be.logCtx[i], be.logCtx[i+1]))
	}
	return strings.Join(s, " ")
}

func (be BasicError) Error() string {
	return FmtError(be)
}

func (be BasicError) GetMsg() string {
	return string(be.Msg)
}

func (be BasicError) GetErr() error {
	return be.Err
}

// MultiError is a slice of errors
type MultiError []error

// ToError returns the object as error interface implementation.
func (be MultiError) ToError() error {
	if len(be) == 0 {
		return nil
	}
	return multiError(be)
}

// multiError is the internal error interface implementation of MultiError.
type multiError []error

func (be multiError) Error() string {
	return FmtErrors(be)
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
	var lines []string
	switch e := e.(type) {
	case ErrorNester:
		lines = strings.Split(e.TopError(), "\n")
	default:
		lines = strings.Split(e.Error(), "\n")
	}
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

// FmtErrors formats a slice of errors for logging.
func FmtErrors(es []error) string {
	s := make([]string, 0, len(es))
	for _, e := range es {
		s = append(s, e.Error())
	}
	return strings.Join(s, "\n")
}
