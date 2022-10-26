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

package common

import (
	"strings"
)

// ErrorMsger allows extracting the message from an error. This means a caller
// can determine the type of error by comparing the returned message with a
// const error string. E.g.:
//
//	if GetErrorMsg(err) == addr.ErrorBadHostAddrType {
//	   // Handle bad host addr error
//	}
type ErrorMsger interface {
	error
	GetMsg() string
}

// ErrorNester allows recursing into nested errors.
type ErrorNester interface {
	error
	TopError() string // should not include the nested error
	GetErr() error
}

// GetNestedError returns the nested error, if any. Returns nil otherwise.
func GetNestedError(e error) error {
	if n, _ := e.(ErrorNester); n != nil {
		return n.GetErr()
	}
	return nil
}

// ErrMsg should be used for error string constants. The constant can then be
// used for Is checking in the calling code.
type ErrMsg string

func (e ErrMsg) Error() string {
	return string(e)
}

// FmtError formats e for logging. It walks through all nested errors, putting each on a new line,
// and indenting multi-line errors.
func FmtError(e error) string {
	var s, ns []string
	for {
		ns, e = innerFmtError(e)
		s = append(s, ns...)
		if e == nil {
			break
		}
	}
	return strings.Join(s, "\n    ")
}

func innerFmtError(e error) ([]string, error) {
	var s []string
	var lines []string
	switch e := e.(type) {
	case ErrorNester:
		lines = strings.Split(e.TopError(), "\n")
	default:
		lines = strings.Split(e.Error(), "\n")
	}
	for i, line := range lines {
		if i == len(lines)-1 && len(line) == 0 {
			// Don't output an empty line if caused by a trailing newline in
			// the input.
			break
		}
		if i == 0 {
			s = append(s, line)
		} else {
			s = append(s, ">   "+line)
		}
	}
	return s, GetNestedError(e)
}

// FmtErrors formats a slice of errors for logging.
func FmtErrors(es []error) string {
	s := make([]string, 0, len(es))
	for _, e := range es {
		s = append(s, e.Error())
	}
	return strings.Join(s, "\n")
}
