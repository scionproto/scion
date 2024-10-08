// Copyright 2018 Anapaya Systems
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

package pktcls

import (
	"fmt"

	"github.com/antlr4-go/antlr/v4"

	"github.com/scionproto/scion/pkg/log"
)

type ErrorListener struct {
	*antlr.DefaultErrorListener
	msg       string
	errorType string
}

func (l *ErrorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol interface{}, line,
	column int, msg string, e antlr.RecognitionException) {
	l.msg = msg
	log.Debug(fmt.Sprintf("%s Error", l.errorType), "err", msg)
}
