// Copyright 2020 Anapaya Systems
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

package feature_test

import (
	"fmt"

	"github.com/scionproto/scion/go/pkg/app/feature"
)

func Example() {
	var featureSet struct {
		One bool `feature:"feature_one"`
		Two bool `feature:"feature_two"`
	}
	if err := feature.Parse([]string{"feature_one"}, &featureSet); err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", featureSet)
	// Output: {One:true Two:false}
}

func Example_notSupported() {
	var featureSet struct {
		One bool `feature:"named"`
	}
	err := feature.Parse([]string{"one"}, &featureSet)
	fmt.Println(err.Error())
	// Output: feature not supported feature="one"
}
