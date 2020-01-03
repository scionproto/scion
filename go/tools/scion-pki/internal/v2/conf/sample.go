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

package conf

// ASSample is the sample AS config.
const ASSample = `# The version of the certificate. Cannot be 0.
version = 1
# Description of the AS and certificate.
description = "AS certificate"
# Array of optional revocation distribution points.
optional_distribution_points = ["2-ff00:0:210"]
# The version of the signing key.
signing_key_version = 1
# The version of the encryption key.
encryption_key_version = 1
# The version of the option revocation key. Omit to disable.
revocation_key_version = 1
# The issuer IA.
issuer_ia = "1-ff00:0:110"
# The certificate version of the issuer certificate
issuer_cert_version = 1

[validity]
    # Time of issuance as UNIX epoch. If 0 will be set to now.
    not_before = 0
    # The validity of the AS certificate as duration string, e.g., 3d or 1w.
    validity = "3d"
`

// IssuerSample is the sample issuer config.
const IssuerSample = `# The version of the certificate. Cannot be 0
version = 1
# Description of the AS and certificate
description = "Issuer certificate"
# Array of optional revocation distribution points.
optional_distribution_points = ["2-ff00:0:210"]
# The version of the AS certificate issuing key.
issuing_key_version = 1
# The version of the option revocation key. Omit to disable.
revocation_key_version = 1
# The version of the issuing TRC.
trc_version = 1

[validity]
    # Time of issuance as UNIX epoch. If 0 will be set to now.
    not_before = 0
    # The validity of the issuer certificate as duration string, e.g., 5d or 1w.
    validity = "5d"
`

// TRCSample is the sample TRC config.
const TRCSample = `# General description for the ISD to be included in the TRC.
description = "ISD 1"
# The version of the TRC. Must not be 0.
version = 2
# The base version of the TRC. Must not be 0.
# (base_version=version indicates a base TRC)
base_version = 1
# The number of voting ASes needed to update the TRC.
voting_quorum = 2
# The grace period for the previous TRC as duration string, e.g., 30m or 6h.
# Must be zero for a base TRC, must not be zero for a non-base TRC.
grace_period = "6h"
# Whether trust resets are allowed for this ISD.
trust_reset_allowed = true
# Votes contains a list of all ASes that cast a vote for the update.
# Must be empty for base TRC.
votes = ["ff00:0:110", "ff00:0:120"]

[validity]
    # Time of issuance as UNIX epoch. If 0 will be set to now.
    not_before = 0
    # The validity of the TRC as duration string, e.g., 180d or 1y.
    validity = "1y"

[primary_ases]
    [primary_ases."ff00:0:110"]
         # Array of attributes. ("authoritative", "core", "issuing", "voting")
         attributes = ["voting"]
         # Online voting key version. Do not set if not voting.
         voting_online_key_version = 1
         # Offline voting key version. Do not set if not voting.
         voting_offline_key_version = 1
    [primary_ases."ff00:0:120"]
         # Array of attributes. ("authoritative", "core", "issuing", "voting")
         attributes = [ "core", "authoritative", "issuing", "voting"]
         # Issuing key version. Do not set if not issuing.
         issuing_key_version = 2
         # Online voting key version. Do not set if not voting.
         voting_online_key_version = 1
         # Offline voting key version. Do not set if not voting.
        voting_offline_key_version = 1
    [primary_ases."ff00:0:130"]
         # Array of attributes. ("authoritative", "core", "issuing", "voting")
         attributes = [ "core", "authoritative"]
`

// KeysSample is the sample keys config.
const KeysSample = `# This section contains keys that are authenticated in the TRC.
# It is only used by primary ASes.
[primary]
    # Issuing key configurations. These keys are required for issuing ASes. Others
    # should omit this section. The key of the entry indicates the key version.
    [primary.issuing.1]
        # The algorithm to use.
        algorithm = "ed25519"
        [primary.issuing.1.validity]
            # Time of when validity starts as UNIX epoch. If 0 will be set to now.
            not_before = 0
            # The validity of the certificate as duration string, e.g., 50w or 1y.
            validity = "1y"
    [primary.issuing.2]
        algorithm = "ed25519"
        [primary.issuing.2.validity]
            not_before = 0
            validity = "1y"

    # Offline voting key configurations. These keys are required for voting ASes.
    # Others should omit this section.
    [primary.offline.1]
        algorithm = "ed25519"
        [primary.offline.1.validity]
            not_before = 0
            validity = "5y"

    # Online voting key configurations. These keys are required for voting ASes.
    # Others should omit this section.
    [primary.online.1]
        algorithm = "ed25519"
        [primary.online.1.validity]
            not_before = 0
            validity = "1y"

# This section contains keys that are authenticated in the issuer certificate.
# It is only used by issuing ASes.
[issuer_cert]
    # AS certificate issuing keys. These keys are required for issuing ASes.
    # Others should omit this section.
    [issuer_cert.issuing.1]
        algorithm = "ed25519"
        [issuer_cert.issuing.1.validity]
            not_before = 0
            validity = "30w"

    # Issuer certificate revocation keys. These keys are optional for issuing ASes.
    # Others should omit this section.
    [issuer_cert.revocation.1]
        algorithm = "ed25519"
        [issuer_cert.revocation.1.validity]
            not_before = 0
            validity = "30w"

# This sections contains keys that are authenticated in the AS certificate.
# It is used by all ASes.
[as_cert]
    # AS certificate signing keys. These keys are required for all ASes.
    [as_cert.signing.1]
        algorithm = "ed25519"
        [as_cert.signing.1.validity]
            not_before = 0
            validity = "15w"

    # AS certificate encryption keys. These keys are required for all ASes.
    [as_cert.encryption.1]
        algorithm = "curve25519xsalsa20poly1305"
        [as_cert.encryption.1.validity]
            not_before = 0
            validity = "15w"

    # AS certificate revocation keys. These keys are optional for all ASes.
    [as_cert.revocation.1]
        algorithm = "ed25519"
        [as_cert.revocation.1.validity]
            not_before = 0
            validity = "15w"
`
