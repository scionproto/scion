// Copyright 2022 Anapaya Systems
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

package fail

import "github.com/scionproto/scion/pkg/private/serrors"

const (
	untyped     = "untyped_key"
	typed   key = "typed_key"
)

var (
	errWrap = serrors.New("wrap")
	errBase = serrors.New("base")
	value   = 1
)

func validParity() {
	serrors.New("some error")
	serrors.Wrap(errWrap, errBase)
	serrors.WrapStr("wrap", errBase)

	serrors.New("some error", "key", value)
	serrors.WithCtx(errBase, "key", value)
	serrors.Wrap(errWrap, errBase, "key", value)
	serrors.WrapStr("wrap", errBase, "key", value)

	serrors.New("some error", "key", value, "key1", value)
	serrors.WithCtx(errBase, "key", value, "key1", value)
	serrors.Wrap(errWrap, errBase, "key", value, "key1", value)
	serrors.WrapStr("wrap", errBase, "key", value, "key1", value)
}

func validTypes() {
	serrors.New("some error", "key", value)
	serrors.New("some error", untyped, value)
	serrors.New("some error", typed, value)
}

func invalidParity() {
	serrors.New("some error", "key")        // want `context should be even: len=1 ctx=\["key"\]`
	serrors.WithCtx(errBase, "key")         // want `context should be even: len=1 ctx=\["key"\]`
	serrors.Wrap(errWrap, errBase, "key")   // want `context should be even: len=1 ctx=\["key"\]`
	serrors.WrapStr("wrap", errBase, "key") // want `context should be even: len=1 ctx=\["key"\]`

	serrors.New("some error", "key", value, "key1")        // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	serrors.WithCtx(errBase, "key", value, "key1")         // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	serrors.Wrap(errWrap, errBase, "key", value, "key1")   // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	serrors.WrapStr("wrap", errBase, "key", value, "key1") // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
}

func invalidType() {
	serrors.New("some error", value, value)        // want `key in context should be string: type="int" name="value"`
	serrors.WithCtx(errBase, value, value)         // want `key in context should be string: type="int" name="value"`
	serrors.Wrap(errWrap, errBase, value, value)   // want `key in context should be string: type="int" name="value"`
	serrors.WrapStr("wrap", errBase, value, value) // want `key in context should be string: type="int" name="value"`
}

func noCtx() {
	serrors.WithCtx(errBase) // want `context is missing:`
}

func duplicateKey() {
	serrors.New("some error", "key", value, "key", value)        // want `duplicate key in context:`
	serrors.WithCtx(errBase, "key", value, "key", value)         // want `duplicate key in context:`
	serrors.Wrap(errWrap, errBase, "key", value, "key", value)   // want `duplicate key in context:`
	serrors.WrapStr("wrap", errBase, "key", value, "key", value) // want `duplicate key in context:`
}

type key string

type multiKey key
