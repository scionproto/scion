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

// ErrMsg is a custom error type used instead of strings in many places. Keeping it for
// compatibility. There are basicError constructors for both string and ErrMsg.
type ErrMsg string

// Error() implements the Go error interface.
func (e ErrMsg) Error() string {
	return string(e)
}

// basicError is an implementation of error that encapsulates various pieces of information besides
// a message. The msg field is *not* any kind of error, it is a string error. This is because
// encapsulating two errors makes the Is() method semantics ambiguous. A generic error can be used
// as a cause. There are constructors from generic error; they encapsulate it as a string error.
type basicError struct {
	msg    ErrMsg
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
	enc.AddString("msg", e.msg.Error())
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
		// e is the result of FromMsg(err). By definition we call that equal.
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

// FromErrCauseStackOpt() returns an error that associates the given message, with the given cause
// (an underlying error) unless nil, and the given context. A stack dump is added if requested and
// apropriate. The returned error implements Is. Is(msg) returns true. Is(cause) returns
// true if cause is not nil. Most other constructors call this one.
func FromMsgCauseStackOpt(msg ErrMsg, cause error, addStack bool, errCtx ...interface{}) error {
	r := basicError{
		msg:    msg,
		fields: errCtxToFields(errCtx),
	}
	if cause != nil {
		// in the odd case where we have two causes. Assume the new one is the one that matters.
		r.cause = cause
	}
	if !addStack {
		return r
	}

	var (
		existingVal basicError
		existingPtr *basicError
	)

	// We attach a stacktrace if there is no basic error cause already. Note that if the innermost
	// basicError was without a stack trace, then there'll never be one. That's to avoid looking
	// for it in every level or every constructor. TB revisisted if necessary.
	if r.cause == nil || !errors.As(cause, &existingVal) && !errors.As(cause, &existingPtr) {
		r.stack = callers()
	}
	return r
}

// FromMsg() returns an error that associates the given message, with the given cause
// (an underlying error) unless nil, and the given context.
// The returned error implements Is. Is(msg) returns true. Is(cause) returns true if cause is not
// nil.
func FromMsg(msg ErrMsg, cause error, errCtx ...interface{}) error {
	return FromMsgCauseStackOpt(msg, cause, false, errCtx...)
}

// FromMsgWithStack() returns an error that associates the given message, with the given cause
// (an underlying error) unless nil, and the given context. A stack dump is added if apropriate. The
// returned error implements Is. Is(msg) returns true. Is(cause) returns true if cause is not nil.
func FromMsgWithStack(msg ErrMsg, cause error, errCtx ...interface{}) error {
	return FromMsgCauseStackOpt(msg, cause, true, errCtx...)
}

// FromStr() returns an error that associates the given message, with the given cause
// (an underlying error) unless nil, and the given context.
// The returned error implements Is and Is(cause) returns true if cause is not nil.
func FromStr(msg string, cause error, errCtx ...interface{}) error {
	return FromMsgCauseStackOpt(ErrMsg(msg), cause, false, errCtx...)
}

// FromStrWithStack() returns an error that associates the given message, with the given cause
// (an underlying error) unless nil, and the given context. A stack dump is added if apropriate. The
// returned error implements Is and Is(cause) returns true if cause is not nil.
func FromStrWithStack(msg string, cause error, errCtx ...interface{}) error {
	return FromMsgCauseStackOpt(ErrMsg(msg), cause, true, errCtx...)
}

// New() creates a new error with the given message and context, with a stack dump.
// It is equivalent to FromMsgWithStack() but returns by reference as is expected of "New()".
// Avoid using this in performance-critical code: it is the most expensive variant. It doesn't
// work well for incremental error construction as it can only be encapsulated as a cause.
// As a result, to make sentinel errors, ErrMsg should be preferred.
func New(msg string, errCtx ...interface{}) error {
	return &basicError{
		msg:    ErrMsg(msg),
		fields: errCtxToFields(errCtx),
		stack:  callers(),
	}
}

// WithCtx() is deprecated. It should never have existed. If you want context added to a generic
// error, you must make it the cause, using one of the FromX() consructors. This shim
// does that for you, supplying a default message prefix. Historically, this function did not add
// a stack dump. It still doesn't.
func WithCtx(err error, errCtx ...interface{}) error {
	return FromMsgCauseStackOpt(ErrMsg("error"), err, false, errCtx...)
}

// Wrap() is deprecated. Use FromMsg(). This shim downgrades the given error to
// a plain string error before use. Is(err) will return false. Code relying on Is(err) == true
// must be adjusted. Historically, this function did not add a stack dump. It still doesn't.
func Wrap(err, cause error, errCtx ...interface{}) error {
	return FromMsgCauseStackOpt(ErrMsg(err.Error()), cause, false, errCtx...)
}

// WrapStr() is deprecated. Use FromStrWithStack()
func WrapStr(msg string, cause error, errCtx ...interface{}) error {
	return FromMsgCauseStackOpt(ErrMsg(msg), cause, true, errCtx...)
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
