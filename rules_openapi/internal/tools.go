// Copyright 2023 SCION Association
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

//go:build tools

package rulesopenapi

import (
	// The bazel rule openapi_generate_go uses oapi-codegen as a build tool.
	// As an easy way to ensure that we have all the appropriate dependencies,
	// import it here in this dummy go file.
	_ "github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen"
)
