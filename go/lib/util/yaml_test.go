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

package util

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/yaml.v2"
)

// Interface assertions
var _ yaml.Marshaler = (*B64Bytes)(nil)
var _ yaml.Unmarshaler = (*B64Bytes)(nil)

func Test_B64B_String(t *testing.T) {
	Convey("String() should return hex-encoded string", t, func() {
		b := B64Bytes{00, 01, 02, 03}
		So(b.String(), ShouldEqual, "00010203")
	})
}

func Test_B64B_MarshalYAML(t *testing.T) {
	Convey("Should marshal to a base64-encoded yaml entry", t, func() {
		b := B64Bytes("hello, world")
		out, _ := yaml.Marshal(&b)
		So(string(out), ShouldEqual, "aGVsbG8sIHdvcmxk\n")
	})
}

func Test_B64B_UnmarshalYAML_YAMLParseError(t *testing.T) {
	Convey("YAML parse error", t, func() {
		var b B64Bytes
		So(yaml.Unmarshal([]byte("a: b"), &b), ShouldNotBeNil)
		So(b, ShouldBeZeroValue)
	})
}

func Test_B64B_UnmarshalYAML_B64DecodeError(t *testing.T) {
	Convey("Base64 decode error", t, func() {
		var b B64Bytes
		So(yaml.Unmarshal([]byte("_"), &b), ShouldNotBeNil)
		So(b, ShouldBeZeroValue)
	})
}

func Test_B64B_UnmarshalYAML_Success(t *testing.T) {
	Convey("Valid sequence unmarshaled", t, func() {
		var b B64Bytes
		So(yaml.Unmarshal([]byte("aGVsbG8sIHdvcmxk"), &b), ShouldBeNil)
		So(b, ShouldResemble, B64Bytes("hello, world"))
	})
}
