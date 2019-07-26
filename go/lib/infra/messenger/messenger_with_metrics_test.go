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

package messenger

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/infra/mock_infra"
)

// TestMessengerWithMetricsCallsUnderlyingMessenger tests that the messenger
// with metrics always calls the underlying messenger function. The test is
// implemented with reflection so that newly added methods are also tested.
func TestMessengerWithMetricsCallsUnderlyingMessenger(t *testing.T) {
	initMetrics()
	msgerType := reflect.TypeOf((*MessengerWithMetrics)(nil))
	for i := 0; i < msgerType.NumMethod(); i++ {
		method := msgerType.Method(i)
		t.Run(fmt.Sprintf("Testing method %s", method.Name), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockMsger := mock_infra.NewMockMessenger(ctrl)
			recorder := mockMsger.EXPECT()
			recorderVal := reflect.ValueOf(recorder)
			expectedCall := recorderVal.MethodByName(method.Name)
			msger := &MessengerWithMetrics{
				messenger: mockMsger,
			}
			msgerVal := reflect.ValueOf(msger)
			var args []reflect.Value
			var argMatchers []reflect.Value
			methodType := method.Type
			for a := 1; a < methodType.NumIn(); a++ {
				if methodType.In(a).Name() == "Context" {
					args = append(args, reflect.ValueOf(context.Background()))
				} else {
					args = append(args, reflect.Zero(methodType.In(a)))
				}
				argMatchers = append(argMatchers, reflect.ValueOf(gomock.Any()))
			}
			expectedCall.Call(argMatchers)
			actualMethod := msgerVal.MethodByName(method.Name)
			actualMethod.Call(args)
		})
	}
}
