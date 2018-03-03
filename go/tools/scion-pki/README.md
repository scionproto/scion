## Overview
`scion-pki` is a tool to generate keys, certificates, and trust root configuration files
used in the SCION control plane PKI.

## Usage
Run `scion-pki -h` and `scion-pki help [command]` for detailed documentation for each command.

## How to setup a new ISD
This section explains how to generate all keys, certificates, and the TRC for an example ISD.

ISD 1 contains the following ASes:
* AS 1, AS 2, AS 3: core ASes
* AS 11: customer of AS 1
* AS 12: customer of AS 2
* AS 13: customer of AS 3

### Setting up the directory structure

`scion-pki` works on a root directory `<root>` that where it will put and look for all the necessary
keys, certificates, TRCs, and configuration files needed for the generation of the PKI entities.
The expected structure is the following:
```
	<root>/
		ISD1/
			trc.ini
			AS1/
				cert.ini
				[core-cert.ini]
				certs/
				keys/
			AS2/
			...
		ISD2/
			AS1/
			...
		...
```
Thus, the first step is to generate the appropriate directory structure. Lets assume for this example
that `<root>` is the current directory, i.e., `.`.

`mkdir -p ISD1/AS{1,2,3,11,12,13}`

### Generating the keys

Now that we have the necessary directory structure in place (`keys` and `certs` directories will be generated
on demand by `scion-pki`), we can generate the keys. First we will generate all keys for the core
ASes.

`scion-pki keys gen -all -core 1-1; scion-pki keys gen -all -core 1-2; scion-pki keys gen -all -core 1-3`

The next step is to generate all the keys for the non-core ASes. For this we simply run

`scion-pki keys gen -all 1-*`

since `scion-pki` won't overwrite already existing keys (unless instructed to with `-f`).

### Generating the TRC

Now that we have generated all the keys, we can generate a TRC. For this, we first need to create 
a `trc.ini` that is used by `scion-pki trc gen` to generate a TRC. We can used

`scion-pki trc template 1-*`

to generate a template config file in `ISD1/trc.ini`. Now, we can adjust the values in `ISD1/trc.ini`
until they look like this:

```
Isd = 1
GracePeriod = 0
CoreASes = 1-1,1-2,1-3
Version = 1
QuorumTRC = 2
Description = "TRC for ISD 1"
Validity = 365
```

Refer to `scion-pki help trc` for documentation on all available parameters.

To generate the TRC, we can run

`scion-pki trc gen 1-*`

which will output the result to `ISD1/ISD1-V1.trc`.

### Generating the certificates

To generate the certificates for each AS, `scion-pki certs gen` expects a `cert.ini` and for core
ASes additionally a `core-cert.ini` containing the parameters used to generate the certificate.

Again, `scion-pki` can generate templates for us:

`scion-pki certs template 1-*`

`scion-pki certs template -core 1-1; scion-pki certs template -core 1-2; scion-pki certs template -core 1-3`

Below are two examples for `ISD1/AS1/core-cert.ini` and `ISD1/AS12/cert.ini`

```
CanIssue      = true
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Subject       = 1-1
Issuer        = 1-1
TRCVersion    = 1
Version       = 1
Validity      = 7
```

```
CanIssue      = false
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Subject       = 1-12
Issuer        = 1-2
TRCVersion    = 1
Version       = 1
Validity      = 3
```

Refer to `scion-pki help certs` for documentation on all available parameters.

We can now finally generate all certificates:

`scion-pki certs gen 1-*`

`scion-pki certs gen` verifies all generated certificates against the TRC to ensure correctness. If
that is not desired for any reason it can be turned of with `-verify=false`.

