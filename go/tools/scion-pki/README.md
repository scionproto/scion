# scion-pki

`scion-pki` is a tool to generate keys, certificates, and trust root
configuration files used in the SCION control plane PKI.

## Table of Contents

- [Overview](#overview)
- [Usage](#usage)
- [Enable autocompletion](#enable-autocompletion)
- [How to setup a sample topology](#how-to-setup-a-sample-topology)
    - [Generating configuration files](#generating-configuration-files)
    - [Generating keys](#generating-keys)
    - [Generating TRCs](#generating-trcs)
    - [Generating issuer certificates](#generating-issuer-certificates)
    - [Generating the AS certificates](#generating-the-as-certificates)
- [Setting up a new ISD](#setting-up-a-new-isd)
    - [Notation](#notation)
    - [Establishing the base TRC](#establishing-the-base-trc)
    - [Creating the issuer certificate](#creating-the-issuer-certificate)
    - [Creating the AS certificates](#creating-the-as-certificates)
- [Adding a new non-primary AS](#adding-a-new-non-primary-AS)
- [Adding a new primary AS](#adding-a-new-primary-AS)
- [Updating the TRC](#updating-the-trc)
- [Renewing the certificates](#renewing-the-certificates)

## Usage

Run `scion-pki -h` or `scion-pki help [command]` for detailed documentation for
each command.

## Enable autocompletion

- `bash`: run `scion-pki autocomplete` and follow the instructions.
- `zsh`: run `scion-pki autocomplete --zsh` and follow the instructions.

## How to setup a sample topology

In this example, we setup a sample SCION topology with two ISDs and multiple
ASes. Each step is explained in the sections bellow.

```bash
# TL;DR
DIR=$(mktemp -d -t scion-pki-XXXXXXXXXX) && cd $DIR
scion-pki v2 tmpl sample > sample.topo
scion-pki v2 tmpl topo sample.topo
scion-pki v2 keys private '*'
scion-pki v2 trcs gen '*'
scion-pki v2 certs issuer '*'
scion-pki v2 certs chain '*'
```

Instead of using the current working directory, a root directory can also be
provided:

```bash
# TL;DR
DIR=$(mktemp -d -t scion-pki-XXXXXXXXXX)
scion-pki v2 tmpl sample > $DIR/sample.topo
scion-pki v2 tmpl topo -d $DIR $DIR/sample.topo
scion-pki v2 keys private -d $DIR '*'
scion-pki v2 trcs gen -d $DIR '*'
scion-pki v2 certs issuer -d $DIR '*'
scion-pki v2 certs chain -d $DIR '*'
```

### Generating configuration files

First, we generate the configuration files for the ISDs and all ASes:

```bash
scion-pki v2 tmpl sample > sample.topo
scion-pki v2 tmpl topo sample.topo
```

This command sets up the following file structure in the `sample` directory:

```bash
sample
├── ISD1
│   ├── ASff00_0_a
│   │   ├── as-v1.toml
│   │   └── keys.toml
│   ├── ASff00_0_b
│   │   ├── as-v1.toml
│   │   └── keys.toml
│   ├── ASff00_0_c
│   │   ├── as-v1.toml
│   │   ├── issuer-v1.toml
│   │   └── keys.toml
│   ├── ASff00_0_d
│   │   ├── as-v1.toml
│   │   └── keys.toml
│   └── trc-v1.toml
└── ISD2
    └── ...
```

There are four types of configuration files:

- `trc-vX.toml`: Configuration file for TRC of version `X` for the given ISD.
  This file allows us to generate TRCs deterministically.
- `as-vX.toml`: Configuration file for AS certificate of version `X` for the AS.
  This file allows us to generate AS certificate deterministically.
- `issuer-vX.toml`: Configuration file for issuer certificate of version `X` for
  the AS. Only issuing ASes have this configuration file .This file allows us to
  generate issuer certificates deterministically.
- `keys.toml`: Configuration file for all keys of an AS. Keys are not generated
  deterministically, make sure not to loose them. This file defines the
  properties for any given key of the AS.

To display a configuration file with explanation use the `tmpl` command:

```bash
scion-pki v2 tmpl trc
scion-pki v2 tmpl as
scion-pki v2 tmpl issuer
scion-pki v2 tmpl keys
```

### Generating keys

Let us now generate the keys for AS `1-ff00:0:c`:

```bash
scion-pki v2 keys private 1-ff00:0:c
```

This will create all the private keys configured in the `sample` directory:

```bash
sample
├── ISD1
│   ├── ASff00_0_c
│   │   ├── ..
│   │   └── keys
│   │       ├── as-decrypt-v1.key
│   │       ├── as-revocation-v1.key
│   │       ├── as-signing-v1.key
│   │       ├── issuer-cert-signing-v1.key
│   │       ├── trc-issuing-v1.key
│   │       ├── trc-voting-offline-v1.key
│   │       └── trc-voting-online-v1.key
```

These keys are not generated deterministically. Make sure not to loose them if
the trust material that authenticates them (TRC or certificate) has already been
disseminated.

To generate the public keys that can be shared with other entities run the
following:

```bash
scion-pki v2 keys public 1-ff00:0:c
```

```bash
sample
├── ISD1
│   ├── ASff00_0_c
│   │   ├── ...
│   │   └── pub
│   │       ├── ISD1-ASff00_0_c-as-decrypt-v1.pub
│   │       ├── ISD1-ASff00_0_c-as-revocation-v1.pub
│   │       ├── ISD1-ASff00_0_c-as-signing-v1.pub
│   │       ├── ISD1-ASff00_0_c-issuer-cert-signing-v1.pub
│   │       ├── ISD1-ASff00_0_c-trc-issuing-v1.pub
│   │       ├── ISD1-ASff00_0_c-trc-voting-offline-v1.pub
│   │       └── ISD1-ASff00_0_c-trc-voting-online-v1.pub
```

The public key names are prepended with the ISD-AS identifier such that other
entities can easily store them in one single location.

In this example, where we have access to all private keys, there is no need to
generated the public keys. They become interesting when we have multiple parties
that only have access to a subset of keys, which will be the normal use case.
Then, operators will exchange those public keys, and put them in the appropriate
locations on the file system. An example interaction with multiple parties is
described in [Setting up a new ISD](#setting-up-a-new-isd).

The `scion-pki` allows for different selectors. The following command will
generate all private keys for all ASes:

```bash
scion-pki v2 keys private '*'
```

For more information on the selector, see: `scion-pki v2 keys -h`

### Generating TRCs

Let us now generate the TRCs for both ISDs:

```bash
scion-pki v2 trcs gen '*'
```

This command is a short-cut that summarizes the three steps for TRC generation
in one step. This is only possible if we have access to all keys. For a scenario
with multiple parties see the [Setting up a new ISD](#setting-up-a-new-ISD)
section.

The generated files are placed in the `trcs` directory.

```bash
sample
├── ISD1
│   ├── ...
│   └── trcs
│       └── ISD1-V1.trc
└── ISD2
    ├── ...
    └── trcs
        └── ISD2-V1.trc
```

The generated TRCs are formatted according to [RFC 7515 JSON Web
Signature(JWS)](https://tools.ietf.org/html/rfc7515). To display them in a human
readable form, run the following:

```bash
scion-pki v2 trcs human ISD1/trcs/ISD1-V1.trc
```

### Generating issuer certificates

In order to build the AS certificates, we need issuer certificates. The are
generated using:

```bash
scion-pki v2 certs issuer '*'
```

The generated files are placed in the 'certs' directory of the respective ASes:

```bash
sample
├── ISD1
│   ├── ASff00_0_c
│   │   ├── ...
│   │   └── certs
│   │       └── ISD1-ASff00_0_c-V1.issuer
```

Again, the generated files are formatted according to [RFC 7515 JSON Web
Signature(JWS)](https://tools.ietf.org/html/rfc7515). To display them in a human
readable form, run the following:

```bash
scion-pki v2 certs human ISD1/ASff00_0_c/certs/ISD1-ASff00_0_c-V1.issuer
```

### Generating the AS certificates

We generate the AS certificates using:

```bash
scion-pki v2 certs chain '*'
```

An AS certificate is always distributed as certificate chain. The chain consists
of the AS certificate itself, and the issuer certificate that authenticates it.

The generated files are placed in the 'certs' directory of the respective ASes:

```bash
sample
├── ISD1
│   ├── ASff00_0_c
│   │   ├── ...
│   │   └── certs
│   │       ├── ...
│   │       └── ISD1-ASff00_0_c-V1.crt
```

To display the certificate chain in a human readable form, run:

```bash
scion-pki v2 certs human ISD1/ASff00_0_c/certs/ISD1-ASff00_0_c-V1.crt
```

With the certificate chains generated, we have all trust material that is
necessary to run a SCION topology.

## Setting up a new ISD

How to setup a new ISD depends on the governance structure of the ISD itself. In
the sample above, we had access to all keys of every AS in the ISD. In normal
operation, this is not the case. In the following, we go over some possible
interactions between multiple parties when setting up an ISD. We consider the
following ASes and their attributes:

- `1-ff00:0:a`: authoritative, core, voting
- `1-ff00:0:b`: voting
- `1-ff00:0:c`: issuing, voting

The setup consists of multiple phases:

- [Establishing the base TRC](#establishing-the-base-trc): The initial Trust Root
  Configuration must be established by the operators.
- [Creating the issuer certificate](#creating-the-issuer-certificate): The
  issuing AS needs to have an issuing certificate to issue the AS certificates
  for the other ASes.
- [Creating the certificate chains](#creating-the-certificate-chains): All ASes
  need a certificate chain to secure the SCION control plane communication.

### Notation

We will show the commands done by the operators of the ASes in the following
sections. `$a` will indicate the commands done by the operator in `1-ff00:0:a`.
Analogously, `$b` and `$c` denote operators of `1-ff00:0:b` and `1-ff00:0:c`
respectively. `$x` denotes a command that is run by all operators.

### Establishing the base TRC

First, the operators setup the necessary folder structure:

```$x mkdir -p ISD1/ASff00_0_{a,b,c}```

Then, the operators need to create their key configurations:

```$x scion-pki v2 tmpl keys > ISD1/ASff00_0_x```

Each operator adapts their keys.toml file with the desired values.
E.g. `$a` deletes the `primary.issuing` and the `issuer_cert` sections.

Now, they generate the private and public keys:

```bash
$x scion-pki v2 keys private 1-ff00:0:x
$x scion-pki v2 keys public 1-ff00:0:x
```

One operator has to take the lead and create the TRC configuration file:

```bash
$a scion-pki v2 tmpl trc > ISD1/trc-v1.toml
```

`$a` modifies the config file according to what the three operators agreed upon.
Especially `grace_period`, `votes`, `validity` and `primary_ases` are important.
Note, in a base TRC - which the initial TRC is - the `grace_period` must be zero
and the votes must be empty. ASes only cast a vote in TRC updates.

The config file should look something like this:

```toml
description = "ISD 1"
version = 1
base_version = 1
voting_quorum = 2
grace_period = "0s"
trust_reset_allowed = true
votes = []

[validity]
  not_before = 1578327410
  validity = "1y"

[primary_ases]
  [primary_ases."ff00:0:a"]
    attributes = ["authoritative", "core", "voting"]
    voting_online_key_version = 1
    voting_offline_key_version = 1
  [primary_ases."ff00:0:b"]
    attributes = ["voting"]
    voting_online_key_version = 1
    voting_offline_key_version = 1
  [primary_ases."ff00:0:c"]
    attributes = ["issuing", "voting"]
    issuing_key_version = 1
    voting_online_key_version = 1
    voting_offline_key_version = 1
```

To generate the prototype TRC, `$a` needs the public keys of `$b`, `$c` which
are provided out of band and are put in `ISD1/ASff00_0_{b,c}/pub` on `$a`'s
file system.

```bash
$a scion-pki v2 trcs proto 1
```

Now `$a` shares the config file (`ISD1/trc-v1.toml`) and the prototype TRC
(`ISD1/trcs/ISD1-V1.parts/ISD1-V1.prototype`) with `$b` and `$c`. After putting
the files in the correct location, all operators attach the signatures. In this
case, the signatures on consist of proof of possessions. In case of a TRC
update, the votes would be cast with the same command. Before doing so, the
operators check the contents of the two provided files to ensure the parameters
are in accordance with the agreed upon values.

```bash
$x cat ISD1/trc-v1.toml
$x scion-pki v2 trcs human ISD1/trcs/ISD1-V1.parts/ISD1-V1.prototype
```

After validating the files are legit, the operators sign them:

```bash
$x scion-pki v2 trcs sign 1-ff00:0:x
```

The three signatures need to be combined into one single signed TRC. To that
end, `$b` and `$c` send their signatures
(`ISD1/trcs/ISD1-V1.parts/ISD1-V1.1-ff00_0_x.sig`) to `$a`.

```bash
$a scion-pki v2 trcs combine 1
```

This creates the fully signed TRC (`ISD1/trcs/ISD1-V1.trc`) that can now be used
by all operators to run the ISD.

### Creating the issuer certificate

The only issuing AS in this scenario is `$c`. The operator needs to first setup
an issuing certificate.

```bash
$c scion-pki v2 tmpl issuer > ISD1/ASff00:0:c/issuer-v1.toml
```

`$c` modifies the config file according to desired values.

The config should look something like this:

```toml
description = "Issuer certificate 1-ff00:0:c"
version = 1
issuing_key_version = 1
trc_version = 1
optional_distribution_points = []

[validity]
  not_before = 1578327410
  validity = "7d"
```

Then the operator creates the issuing certificate:

```bash
$c scion-pki v2 certs issuer 1-ff00:0:c
```

This creates the issuer certificate at `ISD1/ASff00_0_c/certs/ISD1-ASff00_0_c-V1.issuer`

After creating the issuer certificate, the `$c` is ready to create the AS
certificates for itself and the other ASes.

### Creating the AS certificates

Every operator creates an AS certificate configuration with the desired values:

```bash
$x scion-pki v2 tmpl as > ISD1/ASff00:0:x/as-v1.toml
```

After modifying the file with the correct values, it should look something like:

```toml
description = "AS certificate 1-ff00:0:x"
version = 1
signing_key_version = 1
encryption_key_version = 1
issuer_ia = "1-ff00:0:c"
issuer_cert_version = 1
optional_distribution_points = []

[validity]
  not_before = 1578327410
  validity = "3d"

```

`$a` and `$b` share this file plus the referenced public keys
(`ISD1/ASff00_0_{a,b}/pub/ISD1-ASff00_0_{a,b}-as-{signing,decrypt}-v1.pub`)
with `$c`. Now the AS certificates, and thereby the certificate chains can be
generated.

```bash
$c scion-pki v2 certs chain '*'
```

Now the generated chains
(`ISD1/ASff00_0_{a,b}/certs/ISD1-ASff00_0_{a,b}-V1.crt`) are shared with the
respective subject and the ISD is equipped with the trust material to start
ISD-local communication.

## Adding a new non-primary AS

When a new AS `1-ff00:0:d` wants to join the network, `$d` needs to get a
certificate form the issuing AS `1-ff00:0:c`. For this, `$d` creates the
necessary keys and the AS certificate configuration:

```bash
$d mkdir -p ISD1/ASff00_0_d
$d scion-pki v2 tmpl keys > ISD1/ASff00_0_d/keys.toml
$d # Edit the keys.toml with the desired keys
$d scion-pki v2 keys private 1-ff00:0:d
$d scion-pki v2 keys public 1-ff0:0:d
$d scion-pki v2 tmpl as > ISD/ASff0_0_d/as-v1.toml
```

`$d` shares the configuration file plus the referenced public keys
(`ISD1/ASff00_0_d/pub/ISD1-ASff00_0_d-as-{signing,decrypt}-v1.pub`)
with `$c` that puts them on the filesystem.

Now the AS certificate can be issued by `$c`:

```bash
$c scion-pki v2 certs chain 1-ff00:0:d
```

`$c` sends the generated certificate chain
(`ISD1/ASff00_0_d/certs/ISD1-ASff00_0_d-V1.crt`) to `$d` which is now fully
equipped with trust material to join the ISD.

## Adding a new primary AS

Adding a new primary AS requires additional work, since primary AS changes force
a TRC update. First, the current voting ASes need to agree on what attributes
the new primary AS will hold.

For this example, we will consider `1-ff00:0:e` that wants to become a voting
AS. It will first get the current state of the primary ASes (such as the public
keys, the current TRC configuration file, and the latest TRC) and setup the
appropriate folder structure.

Then `$d` needs to setup the keys:

```bash
$d mkdir ISD1/ff00_0_d
$d scion-pki v2 tmpl keys > ISD1/ff00_0_d/keys.toml
$d scion-pki v2 keys private 1-ff00:0:d
$d scion-pki v2 keys public 1-ff00:0:d
```

It shares the public keys
`ISD1/ASff00_0_d/pub/ISD1-ASff00_0_d-trc-voting-{offline,online}-v1.pub` with
the other voting ASes that store them on their local file system.

Then, one operator has to take the lead an generate the configuration file for
the new TRC:

```bash
$a scion-pki v2 tmpl trc > ISD1/trc-v2.toml
```

The file needs to be adapted to include the new AS. Also the `grace_period` must
not be zero, and at least as many voters as `voting_quorum` must be present in
`votes`. The file should look similar to this:

```toml
description = "ISD 1"
version = 2
base_version = 1
voting_quorum = 2
grace_period = "6h"
trust_reset_allowed = true
votes = ["ff00:0:a", "ff00:0:b", "ff00:0:c"]

[validity]
  not_before = 1588327410
  validity = "1y"

[primary_ases]
  [primary_ases."ff00:0:a"]
    attributes = ["authoritative", "core", "voting"]
    voting_online_key_version = 1
    voting_offline_key_version = 1
  [primary_ases."ff00:0:b"]
    attributes = ["voting"]
    voting_online_key_version = 1
    voting_offline_key_version = 1
  [primary_ases."ff00:0:c"]
    attributes = ["issuing", "voting"]
    issuing_key_version = 1
    voting_online_key_version = 1
    voting_offline_key_version = 1
  [primary_ases."ff00:0:d"]
    attributes = ["voting"]
    voting_online_key_version = 1
    voting_offline_key_version = 1
```

Adding a new primary AS is considered a sensitive update and will force all
voters to use their offline key to cast a vote. Since `$d` is not part of the
voting ASes in the previous TRC, it cannot cast a vote. But, since the keys of
`$d` are new, proof of possession must be shown in the new TRC. For this, `$a`
creates a prototype TRC and sends it to all voters plus `$d`. The procedure is
the same as signing the initial TRC:

```bash
# The commands select the latest version. Use --version to specify explicitly.
$a scion-pki v2 trcs proto 1
$x scion-pki v2 trcs sign 1
$a scion-pki v2 trcs combine 1
```

Afterwards, the TRC update can be distributed in the network. For `$d` to be
able to join the network, an AS certificate is required. The process is the same
as in [Adding a new non-primary AS](#adding-a-new-non-primary-AS).

## Updating the TRC

AS we have seen above, updating the TRC is very similar to generating a base TRC
for the operators point of view. Let's look at another example where the set of
primary ASes does not change. First the desired TRC configuration file needs to
be created. In a TRC update, the `grace_period` must not be zero, and at least
as many voters as `voting_quorum` must be present in `votes`.

`ISD1/trc-v2.toml` looks something like:

```toml
description = "ISD 1"
version = 2
base_version = 1
voting_quorum = 2
grace_period = "6h"
trust_reset_allowed = true
votes = ["ff00:0:a", "ff00:0:b", "ff00:0:c"]

[validity]
  not_before = 1588327410
  validity = "1y"

[primary_ases]
  [primary_ases."ff00:0:a"]
    attributes = ["authoritative", "core", "voting"]
    voting_online_key_version = 2
    voting_offline_key_version = 1
  [primary_ases."ff00:0:b"]
    attributes = ["voting"]
    voting_online_key_version = 1
    voting_offline_key_version = 1
  [primary_ases."ff00:0:c"]
    attributes = ["issuing", "voting"]
    issuing_key_version = 1
    voting_online_key_version = 1
    voting_offline_key_version = 1
```

In this update, the `voting_online_key_version` of `$a` changed. This requires
that the updated is signed by `$a` with the offline voting key. Fortunately,
`scion-pki` selects the correct key for voting without any further instruction.
To create and verify an update, the previous TRC version must be available on
the disk.

Again, one operator needs to take the initiative and create the prototype TRC.
The other operators sign the TRC, such that it is combinable. And the TRC update
is done.

## Renewing the certificates

Contrary to TRCs, there is no link between certificate versions. Thus, manually
issuing a new certificate is exactly the same as issuing the initial
certificates. However, certificate renewal is an automated process and only
needs to be done manually in exceptional cases.
