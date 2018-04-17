## Overview
`scion-pki` is a tool to generate keys, certificates, and trust root configuration files
used in the SCION control plane PKI.

## Usage
Run `scion-pki -h` and `scion-pki help [command]` for detailed documentation for each command.

## How to setup a new ISD
This section explains how to generate all keys, certificates, and the TRC for an example ISD.

ISD 1 contains the following ASes:
* AS ff00:0:10, AS ff00:0:20, AS ff00:0:30: core ASes
* AS ff00:0:11: customer of AS ff00:0:10
* AS ff00:0:21: customer of AS ff00:0:20
* AS ff00:0:31: customer of AS ff00:0:30

### Setting up the directory structure

`scion-pki` works on a root directory `<root>` that where it will put and look for all the 
necessary keys, certificates, TRCs, and configuration files needed for the generation of the PKI 
entities.
The expected structure is the following:
```
    <root>/
        ISD1/
            isd.ini
            ASff00_0_10/
                as.ini
                certs/
                keys/
            AS.../
            ...
        ISD2/
            AS.../
            ...
        ...
```
Thus, the first step is to generate the appropriate directory structure. Let's assume for this
example that `<root>` is the current directory, i.e., `.`.

`mkdir -p ISD1/ASff00_0_{10,20,30,11,21,31}`

### Creating the configuration files

The next step is to create all the necessary isd.ini files. We can generate templates with

`scion-pki tmpl isd 1`

to generate a template config file in `ISD1/isd.ini`. Now, we can adjust the values in 
`ISD1/isd.ini`until they look like this:

```
Description = "Test ISD 1"

[TRC]
GracePeriod = 0s
CoreASes = 1-ff00:0:10,1-ff00:0:20,1-ff00:0:30
Version = 1
QuorumTRC = 2
Validity = 365d
```

Refer to `scion-pki help trc` for documentation on all available parameters.

Now we are ready to generate all as.ini files. Again, templates can be generated using

`scion-pki tmpl as 1-*`

Below are examples for `ISD1/ASff00_0_10/as.ini` and `ISD1/ASff00_0_21/as.ini`
```
[AS Certificate]
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Issuer        = 1-ff00:0:10
TRCVersion    = 1
Version       = 1
Validity      = 3d

[Issuer Certificate]
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Issuer        = 1-ff00:0:10
TRCVersion    = 1
Version       = 1
Validity      = 7d

[Key Algorithms]
; Signing algorithm used by Online Key, e.g., ed25519
Online  = ed25519
; Signing algorithm used by Offline Key, e.g., ed25519
Offline = ed25519
```

```
[AS Certificate]
EncAlgorithm  = curve25519xsalsa20poly1305
SignAlgorithm = ed25519
Issuer        = 1-ff00:0:20
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

Building on the previous example, AS 1-ff00:0:20 wants to connect a new customer, 
AS 1-ff00:0:22. To that end, we first create the appropriate subdirectory:

`mkdir ISD1/ASff00_0_22`

Then we can create the template configuration and make the necessary changes:

`scion-pki tmpl as 1-ff00:0:22`

The next step is to create the keys for AS 1-ff00:0:22:

`scion-pki keys gen 1-ff00:0:22`

Finally, we can generate the new certificate:

`scion-pki certs gen 1-ff00:0:22`

## Autocompleting scion-pki commands

For `bash` follow the following instructions

```
./bin/scion-pki autocomplete
sudo mv scion_pki_bash /etc/bash_completion.d
source ~/.bashrc
```

For `zsh` follow the following instructions

```
./bin/scion-pki autocomplete --zsh
mkdir -p ~/.zsh/completion
mv _scion-pki ~/.zsh/completion
echo "fpath=(~/.zsh/completion \$fpath)\nautload -U compinit\ncompinit\nzstyle ':completion:*' menu select=2" >> ~/.zshrc
source ~/.zshrc
```
