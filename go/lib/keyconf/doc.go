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

// Package keyconf defines basic primitives for key configuration.
//
// Type Key allows decoding and encoding PEM files that contain the key with
// attached metadata. The PEM files have special file names based on the type,
// usage, and version of the key. See the encoding and filename example for more
// information.
package keyconf
