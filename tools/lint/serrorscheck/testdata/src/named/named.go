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

package named

import (
	serrors "fake/serrors"

	errors "github.com/scionproto/scion/pkg/private/serrors"
)

var (
	errWrap = errors.New("wrap")
	errBase = errors.New("base")
	value   = 1
)

func fakeImportIgnored() {
	serrors.New("some error", "key")
	serrors.Wrap(errWrap, errBase, "key")
}

func invalid() {
	errors.New("some error", "key")        // want `context should be even: len=1 ctx=\["key"\]`
	errors.WithCtx(errBase, "key")         // want `context should be even: len=1 ctx=\["key"\]`
	errors.Wrap(errWrap, errBase, "key")   // want `context should be even: len=1 ctx=\["key"\]`
	errors.WrapStr("wrap", errBase, "key") // want `context should be even: len=1 ctx=\["key"\]`
}
