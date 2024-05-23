:orphan:

.. _scion-pki_certificate_renew:

scion-pki certificate renew
---------------------------

Renew an AS certificate

Synopsis
~~~~~~~~


'renew' requests a renewed AS certificate from a remote CA control service.

The provided <chain-file> and <key-file> are used to sign the CSR. They must be
valid and verifiable by the CA in order for the request to be served.

The renewed certificate chain is requested with a fresh private key, unless the
\--reuse-key flag is set.

By default, the target CA for the request is extracted from the certificate
chain that is renewed. To select a different CA, you can specify the \--ca flag
with one or multiple target CAs. If multiple CAs are specified, they are tried
in the order that they are declared until the first successful certificate
chain renewal. If none of the declared CAs issued a verifiable certificate chain,
the command returns a non-zero exit code.

The TRCs are used to validate and verify the renewed certificate chain. If the
chain is not verifiable with any of the active TRCs, the certificate chain and,
if applicable, the fresh private key are written to the provided file paths with
the '<CA>.unverified' suffix, where CA is the ISD-AS number of the CA AS that
issued the unverifiable certificate chain.

The resulting certificate chain is written to the file system, either to
<chain-file> or to \--out, if specified.

The fresh private key is is written to the file stystem, either to <key-file>
or to \--out-key, if specified.

Files are not allowed to be overwritten, by default. Either you have to specify
the \--out and \--out-key flags explicitly, or specify the \--force or \--backup
flags. In case the \--backup flag is set, every file that would be overwritten is
renamed to contain a local execution time timestamp before the file extension.
E.g., <filename-base>.<YYYY-MM-DD-HH-MM-SS>.<filename-ext>.

This command supports the \--expires-in flag in order for it to be run in a
periodic task runner (e.g., cronjob). The flag indicates the acceptable remaining
time before certificate expiration. If the remaining time is larger or equal to
the specified value, the command immediately exits with code zero. If the
remaining time is less than the specified value, a renewal run is executed.
The time can either be specified as a time duration or a relative factor of the
existing certificate chain. For the time duration, the following units are
supported: d, h, m, s. The relative factor is supplied as a floating point
number. For example, a factor of 0.75 indicates that the certificate chain
should be renewed after one quarter of its lifetime has passed, and it still
has three quarters of its validity period until it expires.

Unless a subject template is specified, the subject of the existing certificate
chain is used as the subject for the renewal request.

The template is expressed in JSON. A valid example::

  {
    "common_name": "1-ff00:0:110 AS certificate",
    "country": "CH",
    "isd_as": "1-ff00:0:110"
  }

All configurable fields with their type are defined by the following JSON
schema::

  {
    "type": "object",
    "properties": {
      "isd_as":              { "type": "string" },
      "common_name":         { "type": "string" },
      "country":             { "type": "string" },
      "locality":            { "type": "string" },
      "organization":        { "type": "string" },
      "organizational_unit": { "type": "string" },
      "postal_code":         { "type": "string" },
      "province":            { "type": "string" },
      "serial_number":       { "type": "string" },
      "street_address":      { "type": "string" },
    },
    "required": ["isd_as"]
  }

For more information on JSON schemas, see https://json-schema.org/.


::

  scion-pki certificate renew [flags] <chain-file> <key-file>

Examples
~~~~~~~~

::

    scion-pki certificate renew --trc ISD1-B1-S1.trc --backup cp-as.pem cp-as.key
    scion-pki certificate renew --trc ISD1-B1-S1.trc,ISD1-B1-S2.trc --force cp-as.pem cp-as.key
    scion-pki certificate renew --trc ISD1-B1-S1.trc --reuse-key --out cp-as.new.pem cp-as.pem cp-as.key
    scion-pki certificate renew --trc ISD1-B1-S1.trc --backup --expires-in 56h cp-as.pem cp-as.key
    scion-pki certificate renew --trc ISD1-B1-S1.trc --backup --expires-in 0.75 cp-as.pem cp-as.key
    scion-pki certificate renew --trc ISD1-B1-S1.trc --backup --ca 1-ff00:0:110,1-ff00:0:120 cp-as.pem cp-as.key
    scion-pki certificate renew --trc ISD1-B1-S1.trc --backup \
    	--remote 1-ff00:0:110,10.0.0.3 --remote 1-ff00:0:120,172.30.200.2 cp-as.pem cp-as.key


Options
~~~~~~~

::

      --backup                 Back up existing files before overwriting
      --ca strings             Comma-separated list of ISD-AS identifiers of target CAs.
                               The CAs are tried in order until success or all of them failed.
                               --ca is mutually exclusive with --remote
      --common-name string     The common name that replaces the common name in the subject template
      --curve string           The elliptic curve to use (P-256|P-384|P-521) (default "P-256")
      --expires-in string      Remaining time threshold for renewal
      --features strings       enable development features ()
      --force                  Force overwritting existing files
  -h, --help                   help for renew
  -i, --interactive            interactive mode
      --isd-as isd-as          The local ISD-AS to use. (default 0-0)
  -l, --local ip               Local IP address to listen on. (default invalid IP)
      --log.level string       Console logging level verbosity (debug|info|error)
      --no-color               disable colored output
      --no-probe               do not probe paths for health
      --out string             The path to write the renewed certificate chain
      --out-cms string         The path to write the CMS signed CSR sent to the CA
      --out-csr string         The path to write the CSR sent to the CA
      --out-key string         The path to write the fresh private key
      --refresh                set refresh flag for path request
      --remote stringArray     The remote CA address to use for certificate renewal.
                               The address is of the form <ISD-AS>,<IP>. --remote can be specified multiple times
                               and all specified remotes are tried in order until success or all of them failed.
                               --remote is mutually exclusive with --ca.
      --reuse-key              Reuse the provided private key instead of creating a fresh private key
      --sciond string          SCION Daemon address. (default "127.0.0.1:30255")
      --sequence string        Space separated list of hop predicates
      --subject string         The path to the custom subject for the CSR
      --timeout duration       The timeout for the renewal request per CA (default 10s)
      --tracing.agent string   The tracing agent address
      --trc strings            Comma-separated list of trusted TRC files or glob patterns. If more than two TRCs are specified,
                                only up to two active TRCs with the highest Base version are used (required)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki certificate <scion-pki_certificate>` 	 - Manage certificates for the SCION control plane PKI.

