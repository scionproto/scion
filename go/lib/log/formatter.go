// Copyright 2016 ETH Zurich
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

package liblog

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	log "github.com/Sirupsen/logrus"
)

const tsFmt = "2006-01-02T15:04:05.999"

type UTCFormatter struct{}

func (u *UTCFormatter) Format(e *log.Entry) ([]byte, error) {
	var keys []string = make([]string, 0, len(e.Data))
	for k := range e.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "%-5s[%s] %-44s ", strings.ToUpper(e.Level.String()),
		e.Time.UTC().Format(tsFmt), e.Message)
	for _, k := range keys {
		fmt.Fprintf(b, " %s=%+v", k, e.Data[k])
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}
