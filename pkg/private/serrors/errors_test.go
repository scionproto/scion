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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
)

var update = xtest.UpdateGoldenFiles()

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
		assert.ErrorIs(t, errWithCtx, err)
		assert.ErrorIs(t, errWithCtx, errWithCtx)
	})
	t.Run("As", func(t *testing.T) {
		err := &testErrType{msg: "test err"}
		errWithCtx := serrors.WithCtx(err, "someCtx", "someVal")
		var errAs *testErrType
		require.True(t, errors.As(errWithCtx, &errAs))
		assert.Equal(t, err, errAs)
	})
}

func TestWrap(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err := serrors.New("simple err")
		msg := serrors.New("msg err")
		wrappedErr := serrors.Wrap(msg, err, "someCtx", "someValue")
		assert.ErrorIs(t, wrappedErr, err)
		assert.ErrorIs(t, wrappedErr, msg)
		assert.ErrorIs(t, wrappedErr, wrappedErr)
	})
	t.Run("As", func(t *testing.T) {
		err := &testErrType{msg: "test err"}
		msg := serrors.New("msg err")
		wrappedErr := serrors.Wrap(msg, err, "someCtx", "someValue")
		var errAs *testErrType
		require.True(t, errors.As(wrappedErr, &errAs))
		assert.Equal(t, err, errAs)

	})
}

func TestWrapStr(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err := serrors.New("simple err")
		msg := "msg"
		wrappedErr := serrors.WrapStr(msg, err, "someCtx", "someValue")
		assert.ErrorIs(t, wrappedErr, err)
		assert.ErrorIs(t, wrappedErr, wrappedErr)
	})
	t.Run("As", func(t *testing.T) {
		err := &testErrType{msg: "test err"}
		msg := "msg"
		wrappedErr := serrors.WrapStr(msg, err, "someCtx", "someValue")
		var errAs *testErrType
		require.True(t, errors.As(wrappedErr, &errAs))
		assert.Equal(t, err, errAs)

	})
}

func TestNew(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err1 := serrors.New("err msg")
		err2 := serrors.New("err msg")
		assert.ErrorIs(t, err1, err1)
		assert.ErrorIs(t, err2, err2)
		assert.False(t, errors.Is(err1, err2))
		assert.False(t, errors.Is(err2, err1))
		err1 = serrors.New("err msg", "someCtx", "value")
		err2 = serrors.New("err msg", "someCtx", "value")
		assert.ErrorIs(t, err1, err1)
		assert.ErrorIs(t, err2, err2)
		assert.False(t, errors.Is(err1, err2))
		assert.False(t, errors.Is(err2, err1))
	})
}

func TestEncoding(t *testing.T) {
	newLogger := func(b io.Writer) *zap.Logger {
		encoderCfg := zapcore.EncoderConfig{
			MessageKey:     "msg",
			LevelKey:       "level",
			NameKey:        "logger",
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
		}
		return zap.New(
			zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg),
				zapcore.AddSync(b),
				zapcore.DebugLevel),
		)
	}

	testCases := map[string]struct {
		err            error
		goldenFileBase string
	}{
		"new with context": {
			err:            serrors.New("err msg", "k0", "v0", "k1", 1),
			goldenFileBase: "testdata/new-with-context",
		},
		"wrapped string": {
			err: serrors.WrapStr(
				"msg error",
				serrors.New("msg cause"),
				"k0", "v0",
				"k1", 1,
			),
			goldenFileBase: "testdata/wrapped-string",
		},
		"wrapped with context": {
			err: serrors.WrapStr(
				"msg error",
				serrors.New("msg cause", "cause_ctx_key", "cause_ctx_val"),
				"k0", "v0",
				"k1", 1,
			),
			goldenFileBase: "testdata/wrapped-with-string",
		},
		"wrapped error": {
			err: serrors.Wrap(
				serrors.New("msg error"),
				serrors.New("msg cause"),
				"k0", "v0",
				"k1", 1,
			),
			goldenFileBase: "testdata/wrapped-error",
		},
		"error with context": {
			err:            serrors.WithCtx(serrors.New("simple err"), "someCtx", "someValue"),
			goldenFileBase: "testdata/error-with-context",
		},
		"error list": {
			err: serrors.List{
				serrors.New("test err", "ctx1", "val1"),
				serrors.New("test err2"),
			},
			goldenFileBase: "testdata/error-list",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			logFile := tc.goldenFileBase + ".log"
			errFile := tc.goldenFileBase + ".err"

			var b bytes.Buffer
			logger := newLogger(&b)
			logger.Sugar().Infow("Failed to do thing", "err", tc.err)

			logOut := sanitizeLog(b.Bytes())
			// Parse the log output and marshal it again to sort it.
			// The zap encoder is not deterministic for nested maps.
			var parsed map[string]interface{}
			require.NoError(t, json.Unmarshal(logOut, &parsed), string(logOut))
			sorted, err := json.Marshal(parsed)
			require.NoError(t, err)

			if *update {
				require.NoError(t, os.WriteFile(logFile, sorted, 0666))
				require.NoError(t, os.WriteFile(errFile, []byte(tc.err.Error()), 0666))
			}
			goldenLog, err := os.ReadFile(logFile)
			require.NoError(t, err)
			assert.Equal(t, string(goldenLog), string(sorted))

			goldenErr, err := os.ReadFile(errFile)
			require.NoError(t, err)
			assert.Equal(t, string(goldenErr), tc.err.Error())
		})
	}
}

func TestList(t *testing.T) {
	var errors serrors.List
	assert.Nil(t, errors.ToError())
	errors = serrors.List{serrors.New("err1"), serrors.New("err2")}
	combinedErr := errors.ToError()
	assert.NotNil(t, combinedErr)
}

func TestJoinNil(t *testing.T) {
	assert.Nil(t, serrors.Join())
	assert.Nil(t, serrors.Join(nil))
	assert.Nil(t, serrors.Join(nil, nil))
}

func TestJoin(t *testing.T) {
	err1 := serrors.New("err1")
	err2 := serrors.New("err2")
	for _, test := range []struct {
		errs []error
		want serrors.List
	}{{
		errs: []error{err1},
		want: serrors.List{err1},
	}, {
		errs: []error{err1},
		want: serrors.List{err1},
	}, {
		errs: []error{err1, err2},
		want: serrors.List{err1, err2},
	}, {
		errs: []error{err1, nil, err2},
		want: serrors.List{err1, err2},
	}} {
		got := serrors.Join(test.errs...)
		assert.Equal(t, got, test.want)
	}
}

func TestAtMostOneStacktrace(t *testing.T) {
	err := errors.New("core")
	for i := range [20]int{} {
		err = serrors.WrapStr("wrap", err, "level", i)
	}

	var b bytes.Buffer
	logger := zap.New(
		zapcore.NewCore(
			zapcore.NewJSONEncoder(zapcore.EncoderConfig{
				MessageKey:     "msg",
				LevelKey:       "level",
				NameKey:        "logger",
				EncodeLevel:    zapcore.LowercaseLevelEncoder,
				EncodeTime:     zapcore.ISO8601TimeEncoder,
				EncodeDuration: zapcore.StringDurationEncoder,
			}),
			zapcore.AddSync(&b),
			zapcore.DebugLevel),
	)
	logger.Sugar().Infow("Failed to do thing", "err", err)

	require.Equal(t, 1, bytes.Count(b.Bytes(), []byte("stacktrace")))
}

func ExampleNew() {
	err1 := serrors.New("errtxt")
	err2 := serrors.New("errtxt")

	// Self equality always works:
	fmt.Println(errors.Is(err1, err1))
	fmt.Println(errors.Is(err2, err2))
	// On the other hand different errors with same text should not be "equal".
	// That is to prevent that errors with same message in different packages
	// with same text are seen as the same thing:
	fmt.Println(errors.Is(err1, err2))
	// Output:
	// true
	// true
	// false
}

func ExampleWithCtx() {
	// ErrBadL4 is an error defined at package scope.
	var ErrBadL4 = serrors.New("Unsupported L4 protocol")
	addedCtx := serrors.WithCtx(ErrBadL4, "type", "SCTP")

	fmt.Println(addedCtx)
	// Output:
	// Unsupported L4 protocol {type=SCTP}
}

func ExampleWrapStr() {
	// ErrNoSpace is an error defined at package scope.
	var ErrNoSpace = serrors.New("no space")
	wrappedErr := serrors.WrapStr("wrap with more context", ErrNoSpace, "ctx", 1)

	fmt.Println(errors.Is(wrappedErr, ErrNoSpace))
	fmt.Printf("\n%v", wrappedErr)
	// Output:
	// true
	//
	// wrap with more context {ctx=1}: no space
}

func ExampleWrap() {
	// ErrNoSpace is an error defined at package scope.
	var ErrNoSpace = serrors.New("no space")
	// ErrDB is an error defined at package scope.
	var ErrDB = serrors.New("db")
	wrapped := serrors.Wrap(ErrDB, ErrNoSpace, "ctx", 1)

	// Now we can identify specific errors:
	fmt.Println(errors.Is(wrapped, ErrNoSpace))
	// But we can also identify the broader error class ErrDB:
	fmt.Println(errors.Is(wrapped, ErrDB))

	fmt.Printf("\n%v", wrapped)
	// Output:
	// true
	// true
	//
	// db {ctx=1}: no space
}

// sanitizeLog sanitizes the log output so that stack traces look the same on
// all systems including bazel.
func sanitizeLog(log []byte) []byte {
	for _, replacer := range []struct{ pattern, replace string }{
		// serrors Test file
		{`[^\s"]*pkg/private/serrors_test.Test`, "pkg/private/serrors/go_default_test_test.Test"},
		// serrors package
		{`[^\s"]*/pkg/private/serrors`, "pkg/private/serrors"},
		// go sdk
		{`[^\s"]*/src/testing`, "src/testing"},
		// go runtime
		{`[^\s"]*/src/runtime`, "src/runtime"},
	} {
		re := regexp.MustCompile(replacer.pattern)
		log = re.ReplaceAll(log, []byte(replacer.replace))
	}
	return log
}
