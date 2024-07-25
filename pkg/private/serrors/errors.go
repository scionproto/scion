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

type ErrMsg string

func (e ErrMsg) Error() string {
	return string(e)
}

type basicError struct {
	msg    error
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
	if marshaler, ok := e.msg.(zapcore.ObjectMarshaler); ok {
		if err := enc.AddObject("msg", marshaler); err != nil {
			return err
		}
	} else {
		enc.AddString("msg", e.msg.Error())
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
		// This is sick. We cannot have the same provision for *basicError: we have unit test
		// that verify that different newed errors are never equal, even if their content is
		// identical.
	default:
		// e is the result of FromErrXYZ(err). By definition we call that equal. We do not
		// recurse though, so it's not very robust. Also notice that if err is a basicError
		// OBJECT it's the rule above that applies. So all of that is by-design inconsistent.
		return e.msg == err
	}
}

func (e basicError) As(as interface{}) bool {
	return errors.As(e.msg, as)
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

// FromErrCtx() returns an error that associates the given error with the given context.
// The returned error implements Is and Is(err) returns true. The given err argument may be any
// kind of error, including a basicError. No attempt is made at merging the contexts.
func FromErrCtx(err error, errCtx ...interface{}) error {
	return basicError{
		msg:    err,
		fields: errCtxToFields(errCtx),
	}
}

// FromErrCtxWithStack() returns an error that associates the given error with the given context,
// plus a stack dump.
// The returned error implements Is and Is(err) returns true. The given err argument may be any
// kind of error, including a basicError. No attempt is made at merging the contexts. err is not
// assumed to already contain a stack dump.
func FromErrCtxWithStack(err error, errCtx ...interface{}) error {
	return basicError{
		msg:    err,
		fields: errCtxToFields(errCtx),
		stack:  callers(),
	}
}

// FromErrCauseCtx() returns an error that associates the given error, with the given cause (an
// underlying error) and the given context. The returned error implements Is and Is(msg) and
// Is(cause) both return true. The given errors may be of any kind, including basicError. No attempt
// is made at merging them or the given context. The error will carry no stack dump.
func FromErrCauseCtx(msg, cause error, errCtx ...interface{}) error {
	return basicError{
		msg:    msg,
		cause:  cause,
		fields: errCtxToFields(errCtx),
	}
}

// FromErrCauseCtxWithStack() returns an error that associates the given error, with the given
// cause (an underlying error) and the given context, plus a stack dump. The returned error
// implements Is and Is(msg) and Is(cause) both return true. The given errors may be of any kind,
// including basicError. No attempt is made at merging them or the given context. Nor is it assumed
// it may contain a stack dump. If cause is a basicError, it is addumed to contain a stack dump
// so a new one is not created.
func FromErrCauseCtxWithStack(msg, cause error, errCtx ...interface{}) error {
	var (
		existingVal basicError
		existingPtr *basicError
		st          *stack
	)

	// We attach a stacktrace if there is no basic error already. Note that if the innermost
	// basicError was without a stack trace, then there'll never be one. That's to avoid looking
	// for it in every level or every constructor. TB revisisted if necessary.
	if !errors.As(cause, &existingVal) && !errors.As(cause, &existingPtr) {
		st = callers()
	}
	return basicError{
		msg:    msg,
		cause:  cause,
		fields: errCtxToFields(errCtx),
		stack:  st,
	}
}

// FromMsgCtx() is a convenience method equivalent to
// FromErrCtx(ErrMsg(msg), ...)
func FromMsgCtx(msg string, errCtx ...interface{}) error {
	return FromErrCtx(ErrMsg(msg), errCtx...)
}

// FromMsgCtxWithStack() is a convenience method equivalent to
// FromErrCtxWithStack(ErrMsg(msg), ...)
func FromMsgCtxWithStack(msg string, errCtx ...interface{}) error {
	return FromErrCtxWithStack(ErrMsg(msg), errCtx...)
}

// FromMsgCauseCtx() is a convenience method equivalent to
// FromErrCauseCtx(ErrMsg(msg), ...)
func FromMsgCauseCtx(msg string, cause error, errCtx ...interface{}) error {
	return FromErrCauseCtx(ErrMsg(msg), cause, errCtx...)
}

// FromMsgCauseCtxWithStack() is a convenience method equivalent to
// FromErrCauseCtxWithStack(ErrMsg(msg),...)
func FromMsgCauseCtxWithStack(msg string, cause error, errCtx ...interface{}) error {
	return FromErrCauseCtxWithStack(ErrMsg(msg), cause, errCtx...)
}

// New() creates a new error with the given message and context, with a stack dump.
// It is equivalent to FromMsgCtxWithStack() but returns by reference as is expected of "New()".
// Avoid using this in performance-critical code: it is expensive AND allocates from heap.
func New(msg string, errCtx ...interface{}) error {
	return &basicError{
		msg:    ErrMsg(msg),
		fields: errCtxToFields(errCtx),
		stack:  callers(),
	}
}

// WithCtx() is deprecated. It is replaced with FromErrCtx().
// Note that if given a basicError, this function used to attempt the merger of the given context
// and that of err. That almost never happened even when intended and almost nothing cared, so that
// feature is gone.
func WithCtx(err error, errCtx ...interface{}) error {
	return FromErrCtx(err, errCtx...)
}

// Wrap is deprecated. It is replaced by FromErrCauseCtx().
func Wrap(msg, cause error, errCtx ...interface{}) error {
	return FromErrCauseCtx(msg, cause, errCtx...)
}

// WrapStr() is deprecated. It is replaced by FromMsgCauseCtxWithStack()
func WrapStr(msg string, cause error, errCtx ...interface{}) error {
	return FromErrCauseCtxWithStack(ErrMsg(msg), cause, errCtx...)
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

// Join returns an error that wraps the given errors in a List error.
// Any nil error values are discarded.
// Join returns nil if errs contains no non-nil values.
func Join(errs ...error) error {
	n := 0
	for _, err := range errs {
		if err != nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	l := make(List, 0, n)
	for _, err := range errs {
		if err != nil {
			l = append(l, err)
		}
	}
	return l
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
