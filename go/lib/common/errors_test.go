// Copyright 2018 ETH Zurich
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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
)

func TestFmtError(t *testing.T) {
	err := NewBasicError(
		"level0\nlevel0.1",
		fmt.Errorf("level1\nlevel1.1"),
		"k0", "v0", "k1", 1,
	)
	expedtedMsg := `level0
    >   level0.1 k0="v0" k1="1"
    level1
    >   level1.1`
	assert.Equal(t, expedtedMsg, FmtError(err))
}

func TestErrMsg(t *testing.T) {
	errText := "test error string"
	err := ErrMsg(errText)
	assert.Equal(t, errText, err.Error())
}

func TestUnwrap(t *testing.T) {
	baseErr := errors.New("base err")
	noWrapErr := NewBasicError("test no wrap", nil)
	wrapBaseErr := NewBasicError("wrapping base once", baseErr)
	wrapWrapBaseErr := NewBasicError("wrapping wrapper of base", wrapBaseErr)

	assert.Nil(t, xerrors.Unwrap(baseErr))
	assert.Nil(t, xerrors.Unwrap(noWrapErr))
	assert.Equal(t, baseErr, xerrors.Unwrap(wrapBaseErr))
	assert.Equal(t, wrapBaseErr, xerrors.Unwrap(wrapWrapBaseErr))
}

func TestIs(t *testing.T) {
	baseErr := errors.New("base err")
	var baseErrMsg ErrMsg = "base err msg"
	noWrapErr := NewBasicError("test no wrap", nil)
	wrapNoWrapErr := NewBasicError("wrapping basic error", noWrapErr)
	wrapBaseErr := NewBasicError("wrapping base once", baseErr)
	wrapBaseErrMsg := NewBasicError("wrapping base msg once", baseErrMsg)
	wrapWrapBaseErr := NewBasicError("wrapping wrapper of base", wrapBaseErr)

	assert.False(t, xerrors.Is(baseErr, wrapBaseErr))
	assert.False(t, xerrors.Is(noWrapErr, baseErr))
	assert.False(t, xerrors.Is(noWrapErr, wrapNoWrapErr))

	assert.True(t, xerrors.Is(wrapBaseErr, baseErr))
	assert.True(t, xerrors.Is(wrapNoWrapErr, noWrapErr))
	assert.True(t, xerrors.Is(wrapWrapBaseErr, baseErr))
	assert.True(t, xerrors.Is(wrapWrapBaseErr, wrapBaseErr))
	assert.True(t, xerrors.Is(wrapBaseErrMsg, baseErrMsg))

	assert.True(t, xerrors.Is(noWrapErr, ErrMsg("test no wrap")))
	assert.True(t, xerrors.Is(wrapWrapBaseErr, ErrMsg("wrapping base once")))
	assert.True(t, xerrors.Is(wrapNoWrapErr, ErrMsg("test no wrap")))

	assert.True(t, xerrors.Is(ErrMsg("foo"), ErrMsg("foo")))
}

func ExampleErrMsg() {
	var SomeErr ErrMsg = "this is the error msg"

	fmt.Println(xerrors.Is(NewBasicError(SomeErr, nil, "ctx", 1), SomeErr))
	// Output: true
}
