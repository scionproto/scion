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

package serrors

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/xerrors"
)

// ErrorWrapper allows recursing into nested errrors.
type ErrorWrapper interface {
	error
	xerrors.Wrapper
	// TopError should return the top level error without the wrapped ones.
	TopError() string
}

type errOrMsg struct {
	str string
	err error
}

type basicError struct {
	msg    errOrMsg
	logCtx []interface{}
	cause  error
}

func (e basicError) Error() string {
	return FmtError(e)
}

func (e basicError) Is(err error) bool {
	switch other := err.(type) {
	case basicError:
		return e.msg == other.msg
	default:
		if e.msg.err != nil {
			return e.msg.err == err
		}
		return false
	}
}

// TODO do we need self ASing? that would mean the type would need to be public.
func (e basicError) As(as interface{}) bool {
	if e.msg.err != nil {
		return xerrors.As(e.msg.err, as)
	}
	return false
}

func (e basicError) Unwrap() error {
	return e.cause
}

func (e basicError) TopError() string {
	s := make([]string, 0, 1+(len(e.logCtx)/2))
	s = append(s, e.msgString())
	for i := 0; i < len(e.logCtx); i += 2 {
		s = append(s, fmt.Sprintf("%s=\"%v\"", e.logCtx[i], e.logCtx[i+1]))
	}
	return strings.Join(s, " ")
}

func (e basicError) msgString() string {
	if e.msg.err != nil {
		return e.msg.err.Error()
	}
	return e.msg.str
}

// IsTimeout returns whether err is or is caused by a timeout error.
func IsTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return xerrors.As(err, &t) && t.Timeout()
}

// IsTemporary returns whether err is or is caused by a temporary error.
func IsTemporary(err error) bool {
	var t interface{ Temporary() bool }
	return xerrors.As(err, &t) && t.Temporary()
}

// WithCtx returns an error that is the same as the given error but contains the
// additional context. The additional context is printed in the Error method.
func WithCtx(err error, logCtx ...interface{}) error {
	return basicError{
		msg:    errOrMsg{err: err},
		logCtx: logCtx,
	}
}

// Wrap wraps the cause with the msg error and adds context to the resulting
// error.
func Wrap(msg, cause error, logCtx ...interface{}) error {
	return basicError{
		msg:    errOrMsg{err: msg},
		cause:  cause,
		logCtx: logCtx,
	}
}

// WrapStr wraps the cause with an error that has msg in the error message and
// adds the addtional context.
func WrapStr(msg string, cause error, logCtx ...interface{}) error {
	return basicError{
		msg:    errOrMsg{str: msg},
		cause:  cause,
		logCtx: logCtx,
	}
}

// New creates a new error with the given message and context. If no context is
// used prefer using the standard libs New function.
func New(msg string, logCtx ...interface{}) error {
	if len(logCtx) == 0 {
		return errors.New(msg)
	}
	return &basicError{
		msg:    errOrMsg{str: msg},
		logCtx: logCtx,
	}
}

// List is a slice of errors
type List []error

// ToError returns the object as error interface implementation.
func (e List) ToError() error {
	if len(e) == 0 {
		return nil
	}
	return errList(e)
}

// errList is the internal error interface implementation of MultiError.
type errList []error

func (e errList) Error() string {
	return fmtErrors(e)
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
	case ErrorWrapper:
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
	return s, xerrors.Unwrap(e)
}

// fmtErrors formats a slice of errors for logging.
func fmtErrors(errs []error) string {
	s := make([]string, 0, len(errs))
	for _, e := range errs {
		s = append(s, e.Error())
	}
	return strings.Join(s, "\n")
}
