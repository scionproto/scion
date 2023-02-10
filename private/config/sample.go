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

package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// CtxMap contains the context for sample generation.
type CtxMap map[string]string

// WriteSample writes all sample config blocks in order of appearance with
// indentation and header to dst. It panics if an error occurs.
func WriteSample(dst io.Writer, path Path, ctx CtxMap, samplers ...Sampler) {
	var buf bytes.Buffer
	for _, sampler := range samplers {
		buf.Reset()
		if ts, ok := sampler.(TableSampler); ok {
			p := path.Extend(ts.ConfigName())
			writeHeader(dst, p)
			ts.Sample(&buf, p, ctx)
			writeWithIndent(dst, &buf)
			continue
		}
		sampler.Sample(&buf, path, ctx)
		_, err := io.Copy(dst, &buf)
		if err != nil {
			panic(fmt.Sprintf("Unable to write sample err=%s", err))
		}
	}
}

// WriteString writes the string to dst. It panics if an error occurs.
func WriteString(dst io.Writer, s string) {
	_, err := dst.Write([]byte(s))
	if err != nil {
		panic(fmt.Sprintf("Unable to write string err=%s", err))
	}
}

// writeWithIndent writes the contents of src indented to dst.
func writeWithIndent(dst io.Writer, src io.Reader) {
	scanner := bufio.NewScanner(src)
	for scanner.Scan() {
		if len(scanner.Text()) > 0 {
			fmt.Fprintf(dst, "    %s\n", scanner.Text())
		} else {
			fmt.Fprintln(dst)
		}
	}
}

// writeHeader creates a header from path and writes it to dst.
func writeHeader(dst io.Writer, path Path) {
	WriteString(dst, fmt.Sprintf("\n[%s]", strings.Join(path, ".")))
}
