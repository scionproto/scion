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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ctxPair is one item of context info.
type ctxPair struct {
	Key   string
	Value interface{}
}

// errorInfo is a base class for two implementations of error: basicError and joinedError.
type errorInfo struct {
	ctx   *[]ctxPair
	cause error
	stack *stack
}

func (e errorInfo) error() string {
	var buf bytes.Buffer
	if len(*e.ctx) != 0 {
		fmt.Fprint(&buf, " ")
		encodeContext(&buf, *e.ctx)
	}
	if e.cause != nil {
		fmt.Fprintf(&buf, ": %s", e.cause)
	}
	return buf.String()
}

// MarshalLogObject implements zapcore.ObjectMarshaler to have a nicer log
// representation.
func (e errorInfo) marshalLogObject(enc zapcore.ObjectEncoder) error {
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
	for _, pair := range *e.ctx {
		zap.Any(pair.Key, pair.Value).AddTo(enc)
	}
	return nil
}

// StackTrace returns the attached stack trace if there is any.
func (e errorInfo) StackTrace() StackTrace {
	if e.stack == nil {
		return nil
	}
	return e.stack.StackTrace()
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

func mkErrorInfo(cause error, addStack bool, errCtx ...interface{}) errorInfo {
	np := len(errCtx) / 2
	ctx := make([]ctxPair, np)
	for i := 0; i < np; i++ {
		k := errCtx[2*i]
		v := errCtx[2*i+1]
		ctx[i] = ctxPair{Key: fmt.Sprint(k), Value: v}
	}
	sort.Slice(ctx, func(a, b int) bool {
		return ctx[a].Key < ctx[b].Key
	})

	r := errorInfo{
		cause: cause,
		ctx:   &ctx,
	}
	if !addStack {
		return r
	}

	var (
		t1 basicError
		t2 *basicError
		t3 joinedError
		t4 *joinedError
	)

	// We attach a stacktrace if there is no basic error cause already. Note that if the innermost
	// basicError was without a stack trace, then there'll never be one. That's to avoid looking
	// for it in every level or every constructor. TB revisisted if necessary.
	// TODO(jiceatscion): should we define a "stackertracer" interface?
	if r.cause == nil || !(errors.As(cause, &t1) || errors.As(cause, &t2) ||
		errors.As(cause, &t3) || errors.As(cause, &t4)) {

		r.stack = callers()
	}
	return r
}

// basicError is an implementation of error that encapsulates various pieces of information besides
// a message. The msg field is strictly a string.
type basicError struct {
	errorInfo
	msg string
}

func (e basicError) Error() string {
	var buf bytes.Buffer
	buf.WriteString(e.msg)
	buf.WriteString(e.errorInfo.error())
	return buf.String()
}

func (e basicError) Unwrap() error {
	return e.cause
}

// MarshalLogObject implements zapcore.ObjectMarshaler to have a nicer log
// representation.
func (e basicError) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("msg", e.msg)
	return e.errorInfo.marshalLogObject(enc)
}

// WrapStr returns an error that associates the given error, with the given cause (an underlying
// error) unless nil, and the given context.
//
// A stack dump is added unless cause is a basicError (in which case it is assumed to contain a
// stack dump).
//
// The returned error supports Is. Is(cause)returns true.
//
// WrapStr will soon be renamed Wrap, once the name Wrap becomes available. Until then it is ok to
// use wrapStr().
func WrapStr(msg string, cause error, errCtx ...interface{}) error {
	return basicError{
		errorInfo: mkErrorInfo(cause, true, errCtx...),
		msg:       msg,
	}
}

// WrapStrNoStack returns an error that associates the given error, with the given cause
// (an underlying error) unless nil, and the given context. A stack dump is not added.
// if cause is a basicError that contains a stack dump, that stack dump is preserved. The returned
// error supports Is. Is(cause) returns true.
func WrapStrNoStack(msg string, cause error, errCtx ...interface{}) error {
	return basicError{
		errorInfo: mkErrorInfo(cause, false, errCtx...),
		msg:       msg,
	}
}

// New creates a new basicError with the given message and context, plus a stack dump.
// It returns a pointer as the underlying type of the error interface object.
// Avoid using this in performance-critical code: it is the most expensive variant. If used to
// construct other errors, such as with Join, the embedded stack trace and context serve no
// purpose. Therefore, to make sentinel errors, errors.New() should be preferred.
func New(msg string, errCtx ...interface{}) error {
	return &basicError{
		errorInfo: mkErrorInfo(nil, true, errCtx...),
		msg:       msg,
	}
}

// joinedError is an implementation of error that aggregates various pieces of information, around
// an existing error, the base error (for example a unique sentinel error). The base error isn't
// assumed to be of any particular implementation.
type joinedError struct {
	errorInfo
	error error
}

func (e joinedError) Error() string {
	var buf bytes.Buffer
	buf.WriteString(e.error.Error())
	buf.WriteString(e.errorInfo.error())
	return buf.String()
}

func (e joinedError) Unwrap() []error {
	return []error{e.error, e.cause}
}

// MarshalLogObject implements zapcore.ObjectMarshaler to have a nicer log
// representation. The base error is not dissected. It is treated as a most generic error.
func (e joinedError) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("msg", e.error.Error())
	return e.errorInfo.marshalLogObject(enc)
}

// Join returns an error that associates the given error, with the given cause (an underlying error)
// unless nil, and the given context.
//
// A stack dump is added unless cause is a basicError (in which case it is assume to contain a stack
// dump).
//
// The returned error supports Is. If cause isn't nil, Is(cause) returns true. Is(error) returns
// true.
func Join(err, cause error, errCtx ...interface{}) error {
	if err == nil && cause == nil {
		// Pointless. Will not. Also, maintaining backward compatibility with
		// a previous Join function.
		return nil
	}
	return joinedError{
		errorInfo: mkErrorInfo(cause, true, errCtx...),
		error:     err,
	}
}

// JoinNoStack returns an error that associates the given error, with the given cause
// (an underlying error) unless nil, and the given context.
//
// A stack dump is not added. If cause is a basicError and contain a stack dump. That stack dump is
// preserved.
//
// The returned error supports Is. If cause isn't nil, Is(cause) returns true. Is(error) returns
// true.
func JoinNoStack(err, cause error, errCtx ...interface{}) error {
	if err == nil && cause == nil {
		// Pointless. Will not.
		return nil
	}
	return joinedError{
		errorInfo: mkErrorInfo(cause, false, errCtx...),
		error:     err,
	}
}

// Deprecated: WithCtx should never have existed. Depending on intent, use:
//   - Join(err, nil, errCtx): If err has no context to preserve.
//   - WrapStr("some error with context added", err, errctx): if err is an error with error
//     information that needs to be preserved.
//
// This shim does the latter for you for the time being.
//
// WithCtx used to attempt the merger of the given error into the newly created one with
// semantically incorrect results. That feature is gone and the results differ only slightly in the
// formated string output. WithCtx didn't try to add a stack, so this shim doesn't either.
func WithCtx(err error, errCtx ...interface{}) error {
	return WrapStrNoStack("error", err, errCtx...)
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
