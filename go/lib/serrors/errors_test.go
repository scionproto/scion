// Copyright 2019 Anapaya Systems
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

package serrors_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/serrors"
)

type testErrType struct {
	msg string
}

func (e *testErrType) Error() string {
	return e.msg
}

type testToTempErr struct {
	msg       string
	timeout   bool
	temporary bool
	cause     error
}

func (e *testToTempErr) Error() string {
	return e.msg
}

func (e *testToTempErr) Timeout() bool {
	return e.timeout
}

func (e *testToTempErr) Temporary() bool {
	return e.temporary
}

func (e *testToTempErr) Unwrap() error {
	return e.cause
}

func TestIsTimeout(t *testing.T) {
	err := serrors.New("no timeout")
	assert.False(t, serrors.IsTimeout(err))
	wrappedErr := serrors.WrapStr("timeout",
		&testToTempErr{msg: "to", timeout: true})
	assert.True(t, serrors.IsTimeout(wrappedErr))
	noTimeoutWrappingTimeout := serrors.WrapStr("notimeout", &testToTempErr{
		msg:     "non timeout wraps timeout",
		timeout: false,
		cause:   &testToTempErr{msg: "timeout", timeout: true},
	})
	assert.False(t, serrors.IsTimeout(noTimeoutWrappingTimeout))
}

func TestIsTemporary(t *testing.T) {
	err := serrors.New("not temp")
	assert.False(t, serrors.IsTemporary(err))
	wrappedErr := serrors.WrapStr("temp",
		&testToTempErr{msg: "to", temporary: true})
	assert.True(t, serrors.IsTemporary(wrappedErr))
	noTempWrappingTemp := serrors.WrapStr("notemp", &testToTempErr{
		msg:       "non temp wraps temp",
		temporary: false,
		cause:     &testToTempErr{msg: "temp", temporary: true},
	})
	assert.False(t, serrors.IsTemporary(noTempWrappingTemp))
}

func TestWithCtx(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err := serrors.New("simple err")
		errWithCtx := serrors.WithCtx(err, "someCtx", "someValue")
		assert.True(t, xerrors.Is(errWithCtx, err))
		assert.True(t, xerrors.Is(errWithCtx, errWithCtx))
	})
	t.Run("As", func(t *testing.T) {
		err := &testErrType{msg: "test err"}
		errWithCtx := serrors.WithCtx(err, "someCtx", "someVal")
		var errAs *testErrType
		require.True(t, xerrors.As(errWithCtx, &errAs))
		assert.Equal(t, err, errAs)
	})
	t.Run("Fmt", func(t *testing.T) {
		err := serrors.New("simple err")
		errWithCtx := serrors.WithCtx(err, "someCtx", "someValue")
		expectedMsg := `simple err someCtx="someValue"`
		assert.Equal(t, expectedMsg, errWithCtx.Error())
	})
}

func TestWrap(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err := serrors.New("simple err")
		msg := serrors.New("msg err")
		wrappedErr := serrors.Wrap(msg, err, "someCtx", "someValue")
		assert.True(t, xerrors.Is(wrappedErr, err))
		assert.True(t, xerrors.Is(wrappedErr, msg))
		assert.True(t, xerrors.Is(wrappedErr, wrappedErr))
	})
	t.Run("As", func(t *testing.T) {
		err := &testErrType{msg: "test err"}
		msg := serrors.New("msg err")
		wrappedErr := serrors.Wrap(msg, err, "someCtx", "someValue")
		var errAs *testErrType
		require.True(t, xerrors.As(wrappedErr, &errAs))
		assert.Equal(t, err, errAs)

	})
	t.Run("Fmt", func(t *testing.T) {
		err := serrors.New("level0\nlevel0.1")
		cause := serrors.New("level1\nlevel1.1")
		wrappedErr := serrors.Wrap(err, cause, "k0", "v0", "k1", 1)
		expedtedMsg := strings.Join([]string{
			"level0",
			`    >   level0.1 k0="v0" k1="1"`,
			"    level1",
			"    >   level1.1",
		}, "\n")
		assert.Equal(t, expedtedMsg, wrappedErr.Error())
	})
}

func TestWrapStr(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err := serrors.New("simple err")
		msg := "msg"
		wrappedErr := serrors.WrapStr(msg, err, "someCtx", "someValue")
		assert.True(t, xerrors.Is(wrappedErr, err))
		assert.True(t, xerrors.Is(wrappedErr, wrappedErr))
	})
	t.Run("As", func(t *testing.T) {
		err := &testErrType{msg: "test err"}
		msg := "msg"
		wrappedErr := serrors.WrapStr(msg, err, "someCtx", "someValue")
		var errAs *testErrType
		require.True(t, xerrors.As(wrappedErr, &errAs))
		assert.Equal(t, err, errAs)

	})
	t.Run("Fmt", func(t *testing.T) {
		msg := "level0\nlevel0.1"
		cause := serrors.New("level1\nlevel1.1")
		wrappedErr := serrors.WrapStr(msg, cause, "k0", "v0", "k1", 1)
		expedtedMsg := strings.Join([]string{
			"level0",
			`    >   level0.1 k0="v0" k1="1"`,
			"    level1",
			"    >   level1.1",
		}, "\n")
		assert.Equal(t, expedtedMsg, wrappedErr.Error())
	})
}

func TestNew(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err1 := serrors.New("err msg")
		err2 := serrors.New("err msg")
		assert.True(t, xerrors.Is(err1, err1))
		assert.True(t, xerrors.Is(err2, err2))
		assert.False(t, xerrors.Is(err1, err2))
		assert.False(t, xerrors.Is(err2, err1))
		err1 = serrors.New("err msg", "someCtx", "value")
		err2 = serrors.New("err msg", "someCtx", "value")
		assert.True(t, xerrors.Is(err1, err1))
		assert.True(t, xerrors.Is(err2, err2))
		assert.False(t, xerrors.Is(err1, err2))
		assert.False(t, xerrors.Is(err2, err1))
	})
	t.Run("Fmt", func(t *testing.T) {
		err := serrors.New("err msg\n", "k0", "v0", "k1", 1)
		expedtedMsg := strings.Join([]string{
			"err msg",
			`    >    k0="v0" k1="1"`,
		}, "\n")
		assert.Equal(t, expedtedMsg, err.Error())
	})
}

func TestList(t *testing.T) {
	var errors serrors.List
	assert.Nil(t, errors.ToError())
	errors = serrors.List{serrors.New("err1"), serrors.New("err2")}
	combinedErr := errors.ToError()
	assert.NotNil(t, combinedErr)
	assert.Equal(t, "err1\nerr2", combinedErr.Error())
}

func ExampleNew() {
	err1 := serrors.New("errtxt")
	err2 := serrors.New("errtxt")

	// Self equality always works:
	fmt.Println(xerrors.Is(err1, err1))
	fmt.Println(xerrors.Is(err2, err2))
	// On the other hand different errors with same text should not be "equal".
	// That is to prevent that errors with same message in different packages
	// with same text are seen as the same thing:
	fmt.Println(xerrors.Is(err1, err2))

	// Output:
	// true
	// true
	// false
}

func ExampleWrapStr() {
	// ErrNoSpace is an error defined at package scope.
	var ErrNoSpace = serrors.New("no space")

	wrappedErr := serrors.WrapStr("wrap with more context", ErrNoSpace, "ctx", 1)
	fmt.Println(xerrors.Is(wrappedErr, ErrNoSpace))
	// Output: true
}

func ExampleWrap() {
	// ErrNoSpace is an error defined at package scope.
	var ErrNoSpace = serrors.New("no space")
	// ErrDB is an error defined at package scope.
	var ErrDB = serrors.New("db")

	wrapped := serrors.Wrap(ErrDB, ErrNoSpace, "ctx", 1)
	// Now we can identify specific errors:
	fmt.Println(xerrors.Is(wrapped, ErrNoSpace))

	// But we can also identify the broader error class ErrDB:
	fmt.Println(xerrors.Is(wrapped, ErrDB))

	// Output:
	// true
	// true
}
