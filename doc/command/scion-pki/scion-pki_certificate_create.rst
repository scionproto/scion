:orphan:

.. _scion-pki_certificate_create:

scion-pki certificate create
----------------------------

Create a certificate or certificate signing request

Synopsis
~~~~~~~~


'create' generates a certificate or a certificate signing request (CSR).

The command takes the following positional arguments:

- <subject-template> is the template for the certificate subject distinguished name.
- <crt-file> is the file path where the certificate or certificate requests is
  written to. The parent directory must exist and must be writable.
- <key-file> is the file path where the fresh private key is written to. The
  parent directory must exist and must be writable.

By default, the command creates a SCION control-plane PKI AS certificate. Another
certificate type can be selected by providing the \--profile flag. If a certificate
chain is desired, specify the \--bundle flag.

A fresh key is created in the provided <key-file>, unless the \--key flag is set.
If the \--key flag is set, an existing private key is used and the <key-file> is
ignored.

The \--ca and \--ca-key flags are required if a AS certificate or CA certificate
is being created. Otherwise, they are not allowed.

The \--not-before and \--not-after flags can either be a timestamp or a relative
time offset from the current time.

A timestamp can be provided in two different formats: unix timestamp and
RFC 3339 timestamp. For example, 2021-06-24T12:01:02Z represents 1 minute and 2
seconds after the 12th hour of June 26th, 2021 in UTC.

The relative time offset can be formated as a time duration string with the
following units: y, w, d, h, m, s. Negative offsets are also allowed. For
example, -1h indicates the time of tool invocation minus one hour. Note that
\--not-after is relative to the current time if a relative time offset is used,
and not to \--not-before.

The <subject-template> is the template for the distinguished name of the
requested certificate and must either be a x.509 certificate or a JSON file.
The common name can be overridden by supplying the \--common-name flag.

If it is a x.509 certificate, the subject of the template is used as the subject
of the created certificate or certificate chain request.

A valid example for a JSON formatted template::

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

  scion-pki certificate create [flags] <subject-template> <cert-file> <key-file>

Examples
~~~~~~~~

::

    scion-pki certificate create --profile cp-root subject.tmpl cp-root.crt cp-root.key
    scion-pki certificate create --ca cp-ca.crt --ca-key cp-ca.key subject.tmpl chain.pem cp-as.key
    scion-pki certificate create --csr subject.tmpl chain.csr cp-as.key

Options
~~~~~~~

::

      --bundle               Bundle the certificate with the issuer certificate as a certificate chain
      --ca string            The path to the issuer certificate
      --ca-key string        The path to the issuer private key used to sign the new certificate
      --ca-kms string        The uri to configure a Cloud KMS or an HSM used for signing the certificate.
      --common-name string   The common name that replaces the common name in the subject template
      --csr                  Generate a certificate signign request instead of a certificate
      --curve string         The elliptic curve to use (P-256|P-384|P-521) (default "P-256")
      --force                Force overwritting existing files
  -h, --help                 help for create
      --key string           The path to the existing private key to use instead of creating a new one
      --kms string           The uri to configure a Cloud KMS or an HSM.
      --not-after time       The NotAfter time of the certificate. Can either be a timestamp or an offset.
                             
                             If the value is a timestamp, it is expected to either be an RFC 3339 formatted
                             timestamp or a unix timestamp. If the value is a duration, it is used as the
                             offset from the current time. (default depends on profile)
      --not-before time      The NotBefore time of the certificate. Can either be a timestamp or an offset.
                             
                             If the value is a timestamp, it is expected to either be an RFC 3339 formatted
                             timestamp or a unix timestamp. If the value is a duration, it is used as the
                             offset from the current time. (default 0s)
      --profile string       The type of certificate to generate (cp-as|cp-ca|cp-root|sensitive-voting|regular-voting) (default "cp-as")

SEE ALSO
~~~~~~~~

* :ref:`scion-pki certificate <scion-pki_certificate>` 	 - Manage certificates for the SCION control plane PKI.

