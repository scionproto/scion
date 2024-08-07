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
	"reflect"
	"sort"
	"strings"

	"go.uber.org/zap/zapcore"
)

// ErrMsg is a custom error type used instead of strings in many places. It is a good type to use
// for sentinel errors. There are basicError constructors for both string and error.
type ErrMsg string

// Error implements the Go error interface.
func (e ErrMsg) Error() string {
	return string(e)
}

// basicError is an implementation of error that encapsulates various pieces of information besides
// a message. The msg field is any kind of error, inluding a basicError. It receives no  particular
// treatment in that case. Most notably constructing an basicError E, such that E.msg.msg == T does
// *not* imply that E.Is(T) is true. The intended use of a basicError as msg is to support the
// extent use of sentinel error created by New(). For that purpose simpler errors such as ErrMsg
// would be preferable.
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
		// When error's underlying value isn't a pointer error.Is() calls us because basicError
		// isn't comparable. This check is loose but about the only real use case is E.Is(E).
		// We still need to make sure we don't panic if the two msg fields are non-comparable.
		// (That's unlikely given how basicError is used, but entirely feasible).
		if e.msg != nil && other.msg != nil && !(reflect.TypeOf(e.msg).Comparable() &&
			reflect.TypeOf(other.msg).Comparable()) {
			return false
		}
		return e.msg == other.msg

		// No special case if the underlying value is a basicError pointer. For identical pointers,
		// this method is never called. For different error pointers we want them to be always
		// different, except for... see below.

	default:
		// If err was created with New(), its underlying value is a pointer, so it matches this
		// case.
		return e.msg == err // If true, e is the result of FromMsg(err, ...), so equal.
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

// FromErrStackOpt returns an error that associates the given error, with the given cause
// (an underlying error) unless nil, and the given context. A stack dump is added if requested and
// cause isn't a basicError. The returned error implements Is. Is(err) returns true. Is(cause)
// returns true. Any stack dump attached to err (if err is a basicError) is subsequently ignored.
// The result of err.Error will be part of the result of Error. Most other constructors call
// this one.
func FromErrStackOpt(err error, cause error, addStack bool, errCtx ...interface{}) error {
	r := basicError{
		msg:    err,
		cause:  cause, // If msg itself has a cause, we don't care about it.
		fields: errCtxToFields(errCtx),
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

// FromMsg returns an error that associates the given error, with the given cause
// (an underlying error) unless nil, and the given context.
// The returned error implements Is. Is(err) returns true. Is(cause) returns true if cause is not
// nil.
func FromErr(err, cause error, errCtx ...interface{}) error {
	return FromErrStackOpt(err, cause, false, errCtx...)
}

// FromErrWithStack returns an error that associates the given error, with the given cause
// (an underlying error) unless nil, and the given context. A stack dump is added if cause isn't
// a basicError. The returned error implements Is. Is(err) returns true. Is(cause) returns true.
func FromErrWithStack(err, cause error, errCtx ...interface{}) error {
	return FromErrStackOpt(err, cause, true, errCtx...)
}

// FromStr returns an error that associates the given message, with the given cause
// (an underlying error) unless nil, and the given context.
// The returned error implements Is and Is(cause) returns true.
func FromStr(msg string, cause error, errCtx ...interface{}) error {
	return FromErrStackOpt(ErrMsg(msg), cause, false, errCtx...)
}

// FromStrWithStack returns an error that associates the given message, with the given cause
// (an underlying error) unless nil, and the given context. A stack dump is added if cause isn't a
// basicError. The returned error implements Is and Is(cause) returns true.
func FromStrWithStack(msg string, cause error, errCtx ...interface{}) error {
	return FromErrStackOpt(ErrMsg(msg), cause, true, errCtx...)
}

// New creates a new error with the given message and context, with a stack dump.
// It is equivalent to FromMsgWithStack() but returns by reference as is expected of "New()".
// Avoid using this in performance-critical code: it is the most expensive variant. If used to
// construct other errors, such as with FromErr(), the embedded stack trace and context serve no
// purpose. Therefore to make sentinel errors, ErrMsg should be preferred.
func New(msg string, errCtx ...interface{}) error {
	return &basicError{
		msg:    ErrMsg(msg),
		fields: errCtxToFields(errCtx),
		stack:  callers(),
	}
}

// Deprecated: WithCtx should never have existed. Use FromErr or FromStr to create
// a new error with the original as the cause. This shim does it for you for the time being.
// WithCtx used to attempt the merger of the given error into the newly created one with
// semantically incorrect results. That feature is gone and the results differ only slightly in the
// formated string output. WithCtx still doesn't add a stack.
func WithCtx(err error, errCtx ...interface{}) error {
	return FromErrStackOpt(ErrMsg("error"), err, false, errCtx...)
}

// Deprecated: Wrap has been renamed FromErr. FromErr and the historical do differ very slightly:
// any stack dump that might have be attached to err is ignored when logging. Like before, no stack
// dump is added to the returned error.
func Wrap(err, cause error, errCtx ...interface{}) error {
	return FromErrStackOpt(err, cause, false, errCtx...)
}

// Deprecated: WrapStr has been renamed FromStrWithStack.
func WrapStr(msg string, cause error, errCtx ...interface{}) error {
	return FromErrStackOpt(ErrMsg(msg), cause, true, errCtx...)
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
