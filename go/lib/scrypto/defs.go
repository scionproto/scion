// Copyright 2018 ETH Zurich
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

package scrypto

import "encoding/base64"

// LatestVer is the wildcard version indicating the highest available version
// when requesting certificate chains and TRCs.
const LatestVer uint64 = 0

// Base64 is the base64 encoding used when packing and unpacking encoded data.
// In accordance with rfc7515 (see https://tools.ietf.org/html/rfc7515#section-2),
// this is the URL safe encoding with padding omitted.
var Base64 = base64.RawURLEncoding
