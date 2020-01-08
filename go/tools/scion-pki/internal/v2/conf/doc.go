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

// Package conf defines the configuration files for the scion-pki tool.
//
// Config files
//
// The way scion-pki generates trust material, such as TRCs or certificates, can
// be configured through configuration files. There are four configuration file
// types:
//
// TRC: For each TRC version, there is exactly one configuration file. The
// config specifies the contents of the TRC (e.g. the validity period, the
// voting ASes and which keys to use).
//
// Keys: Each AS has a keys configuration file that specifies all keys with
// their version, validity and algorithm.
//
// AS certificate: For each AS certificate version, there is exactly one
// configuration file. The config specifies the contents of the certificate
// (e.g. the validity period, the issuing AS, and which keys to use).
//
// Issuer certificate: For each Issuer certificate version, there is exactly one
// configuration file. The config specifies the contents of the certificate
// (e.g. the validity period, the issuing AS, and which keys to use).
//
// Directory Structure
//
// The directory structure how config files are arranged and the file naming is
// rigid. A sample tree is shown below. This package exposes a set of helper
// functions to determine the correct file names.
//
//    <root>/
//    ├── ISD1
//    │   ├── ASff00_0_110
//    │   │   ├── as-v1.toml
//    │   │   ├── iss-v1.toml
//    │   │   ├── keys.toml
//    │   │   ...
//    │   ├── ASff00_0_120
//    │   │   ├── as-v1.toml
//    │   │   ├── as-v2.toml
//    │   │   ├── keys.toml
//    │   │   ...
//    │   ├── ASff00_0_130
//    │   │    ...
//    │   ├── trc-v1.toml
//    │   ...
//    ├── ISD2
//        ...
package conf
