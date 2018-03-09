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

`scion-pki` works on a root directory `<root>` that where it will put and look for all the 
necessary keys, certificates, TRCs, and configuration files needed for the generation of the PKI 
entities.
The expected structure is the following:
```
    <root>/
        ISD1/
            isd.ini
            AS1/
                as.ini
                certs/
                keys/
            AS2/
            ...
        ISD2/
            AS1/
            ...
        ...
```
Thus, the first step is to generate the appropriate directory structure. Let's assume for this
example that `<root>` is the current directory, i.e., `.`.

`mkdir -p ISD1/AS{1,2,3,11,12,13}`

### Creating the configuration files

The next step is to create all the necessary isd.ini files. We can generate templates with

`scion-pki tmpl isd 1`

to generate a template config file in `ISD1/isd.ini`. Now, we can adjust the values in 
`ISD1/isd.ini`until they look like this:

```
Description = "Test ISD 1"

[TRC]
GracePeriod = 0s
CoreASes = 1-1,1-2,1-3
Version = 1
QuorumTRC = 2
Validity = 365d
```

Refer to `scion-pki help trc` for documentation on all available parameters.

Now we are ready to generate all as.ini files. Again, templates can be generated using

`scion-pki tmpl as 1-*`

Below are examples for `ISD1/AS1/as.ini` and `ISD1/AS12/as.ini`
```
[AS Certificate]
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Issuer        = 1-1
TRCVersion    = 1
Version       = 1
Validity      = 3d

[Issuer Certificate]
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Issuer        = 1-1
TRCVersion    = 1
Version       = 1
Validity      = 7d
```

```
[AS Certificate]
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Issuer        = 1-2
TRCVersion    = 1
Version       = 1
Validity      = 3d
```

Refer to `scion-pki help certs` for documentation on all available parameters.

### Generating the keys, the TRC, and the certificates

Now that we have the necessary config files and the directory structure in place (`keys` and
`certs` directories will be generated on demand by `scion-pki`), we can generate the keys. 

`scion-pki keys gen 1-*`

the TRC

`scion-pki trc gen 1`

and the certificates

`scion-pki certs gen 1-*`

`scion-pki certs gen` verifies all generated certificates against the TRC to ensure correctness. If
that is not desired for any reason it can be turned of with `-verify=false`.

## How to add a new customer AS

Building on the previous example, AS 1-2 wants to connect a new customer, AS 1-22. To that end, we
first create the appropriate subdirectory:

`mkdir ISD1/AS22`

Then we can create the template configuration and make the necessary changes:

`scion-pki tmpl as 1-22`

The next step is to create the keys for AS 1-22:

`scion-pki keys gen 1-22`

Finally, we can generate the new certificate:

`scion-pki certs gen 1-22`

