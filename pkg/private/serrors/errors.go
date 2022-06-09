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

// Package serrors provides enhanced errors. Errors created with serrors can
// have additional log context in form of key value pairs. The package provides
// wrapping methods. The returned errors support new Is and As error
// functionality. For any returned error err, errors.Is(err, err) is always
// true, for any err which wraps err2 or has err2 as msg, errors.Is(err, err2)
// is always true, for any other combination of errors errors.Is(x,y) can be
// assumed to return false.
package serrors

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.uber.org/zap/zapcore"
)

type errOrMsg struct {
	str string
	err error
}

func (m errOrMsg) Error() string {
	if m.err != nil {
		return m.err.Error()
	}
	return m.str
}

func (m errOrMsg) addToEncoder(enc zapcore.ObjectEncoder) error {
	if m.err != nil {
		if marshaler, ok := m.err.(zapcore.ObjectMarshaler); ok {
			return enc.AddObject("msg", marshaler)
		}
		enc.AddString("msg", m.err.Error())
		return nil
	}
	enc.AddString("msg", m.str)
	return nil
}

type basicError struct {
	msg    errOrMsg
	fields map[string]interface{}
	cause  error
	stack  *stack
}

func (e basicError) Error() string {
	var buf bytes.Buffer
	buf.WriteString(e.msg.Error())
	if len(e.fields) != 0 {
		fmt.Fprint(&buf, " ")
		encodeContext(&buf, e.ctxPairs())
	}
	if e.cause != nil {
		fmt.Fprintf(&buf, ": %s", e.cause)
	}
	return buf.String()
}

// MarshalLogObject implements zapcore.ObjectMarshaler to have a nicer log
// representation.
func (e basicError) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if err := e.msg.addToEncoder(enc); err != nil {
		return err
	}
	if e.cause != nil {
		if m, ok := e.cause.(zapcore.ObjectMarshaler); ok {
			if err := enc.AddObject("cause", m); err != nil {
				return err
			}
		} else {
			enc.AddString("cause", e.cause.Error())
		}
	}
	if e.stack != nil {
		if err := enc.AddArray("stacktrace", e.stack); err != nil {
			return err
		}
	}
	for k, v := range e.fields {
		if err := enc.AddReflected(k, v); err != nil {
			return err
		}
	}
	return nil
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

func (e basicError) As(as interface{}) bool {
	if e.msg.err != nil {
		return errors.As(e.msg.err, as)
	}
	return false
}

func (e basicError) Unwrap() error {
	return e.cause
}

// StackTrace returns the attached stack trace if there is any.
func (e basicError) StackTrace() StackTrace {
	if e.stack == nil {
		return nil
	}
	return e.stack.StackTrace()
}

func (e basicError) ctxPairs() []ctxPair {
	fields := make([]ctxPair, 0, len(e.fields))
	for k, v := range e.fields {
		fields = append(fields, ctxPair{Key: k, Value: v})
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Key < fields[j].Key
	})
	return fields
}

// IsTimeout returns whether err is or is caused by a timeout error.
func IsTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// IsTemporary returns whether err is or is caused by a temporary error.
func IsTemporary(err error) bool {
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

// WithCtx returns an error that is the same as the given error but contains the
// additional context. The additional context is printed in the Error method.
// The returned error implements Is and Is(err) returns true.
// Deprecated: use WrapStr or New instead.
func WithCtx(err error, errCtx ...interface{}) error {
	if top, ok := err.(basicError); ok {
		return basicError{
			msg:    top.msg,
			fields: combineFields(top.fields, errCtxToFields(errCtx)),
			cause:  top.cause,
			stack:  top.stack,
		}
	}

	return basicError{
		msg:    errOrMsg{err: err},
		fields: errCtxToFields(errCtx),
	}
}

// Wrap wraps the cause with the msg error and adds context to the resulting
// error. The returned error implements Is and Is(msg) and Is(cause) returns
// true.
// Deprecated: use WrapStr instead.
func Wrap(msg, cause error, errCtx ...interface{}) error {
	return basicError{
		msg:    errOrMsg{err: msg},
		cause:  cause,
		fields: errCtxToFields(errCtx),
	}
}

// WrapStr wraps the cause with an error that has msg in the error message and
// adds the additional context. The returned error implements Is and Is(cause)
// returns true.
func WrapStr(msg string, cause error, errCtx ...interface{}) error {
	var (
		existingVal basicError
		existingPtr *basicError
		st          *stack
	)

	// We attach a stacktrace if there is no basic error already.
	if !errors.As(cause, &existingVal) && !errors.As(cause, &existingPtr) {
		st = callers()
	}
	return basicError{
		msg:    errOrMsg{str: msg},
		cause:  cause,
		fields: errCtxToFields(errCtx),
		stack:  st,
	}
}

// New creates a new error with the given message and context.
func New(msg string, errCtx ...interface{}) error {
	if len(errCtx) == 0 {
		return &basicError{
			msg:   errOrMsg{str: msg},
			stack: callers(),
		}
	}
	return &basicError{
		msg:    errOrMsg{str: msg},
		fields: errCtxToFields(errCtx),
		stack:  callers(),
	}
}

// List is a slice of errors.
type List []error

// Error implements the error interface.
func (e List) Error() string {
	s := make([]string, 0, len(e))
	for _, err := range e {
		s = append(s, err.Error())
	}
	return fmt.Sprintf("[ %s ]", strings.Join(s, "; "))
}

// ToError returns the object as error interface implementation.
func (e List) ToError() error {
	if len(e) == 0 {
		return nil
	}
	return e
}

// MarshalLogArray implements zapcore.ArrayMarshaller for nicer logging format
// of error lists.
func (e List) MarshalLogArray(ae zapcore.ArrayEncoder) error {
	for _, err := range e {
		if m, ok := err.(zapcore.ObjectMarshaler); ok {
			if err := ae.AppendObject(m); err != nil {
				return err
			}
		} else {
			ae.AppendString(err.Error())
		}
	}
	return nil
}

func errCtxToFields(errCtx []interface{}) map[string]interface{} {
	if len(errCtx) == 0 {
		return nil
	}
	fields := make(map[string]interface{}, len(errCtx)/2)
	for i := 0; i < len(errCtx)-1; i += 2 {
		fields[fmt.Sprint(errCtx[i])] = errCtx[i+1]
	}
	return fields
}

func combineFields(a, b map[string]interface{}) map[string]interface{} {
	fields := make(map[string]interface{}, len(a)+len(b))
	for k, v := range a {
		fields[k] = v
	}
	for k, v := range b {
		fields[k] = v
	}
	return fields
}

type ctxPair struct {
	Key   string
	Value interface{}
}

func encodeContext(buf io.Writer, pairs []ctxPair) {
	fmt.Fprint(buf, "{")
	for i, p := range pairs {
		fmt.Fprintf(buf, "%s=%v", p.Key, p.Value)
		if i != len(pairs)-1 {
			fmt.Fprint(buf, "; ")
		}
	}
	fmt.Fprintf(buf, "}")
}

func (s *stack) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := 0; i < len(*s); i++ {
		f := Frame((*s)[i])
		t, err := f.MarshalText()
		if err != nil {
			return err
		}
		enc.AppendByteString(t)
	}
	return nil
}
