:orphan:

.. _scion-pki_certificate_sign:

scion-pki certificate sign
--------------------------

Sign a certificate based on a certificate signing request

Synopsis
~~~~~~~~


'sign' creates a certificate based on a certificate signing request (CSR).

The command takes the following positional arguments:

- <csr-file> is the file path where the PEM-encoded certificate signing request is located.

By default, the command creates a SCION control-plane PKI AS certificate. Another
certificate type can be selected by providing the \--profile flag. If a certificate
chain is desired, specify the \--bundle flag.

The \--ca and \--ca-key flags are required.

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


::

  scion-pki certificate sign [flags] <csr-file>

Examples
~~~~~~~~

::

    scion-pki certificate sign --ca cp-ca.crt --ca-key cp-ca.key cp-as.csr
    scion-pki certificate sign --profile cp-ca --ca cp-root.crt --ca-key cp-root.key cp-ca.csr 

Options
~~~~~~~

::

      --bundle            Bundle the certificate with the issuer certificate as a certificate chain
      --ca string         The path to the issuer certificate
      --ca-key string     The path to the issuer private key used to sign the new certificate
  -h, --help              help for sign
      --not-after time    The NotAfter time of the certificate. Can either be a timestamp or an offset.
                          
                          If the value is a timestamp, it is expected to either be an RFC 3339 formatted
                          timestamp or a unix timestamp. If the value is a duration, it is used as the
                          offset from the current time. (default depends on profile)
      --not-before time   The NotBefore time of the certificate. Can either be a timestamp or an offset.
                          
                          If the value is a timestamp, it is expected to either be an RFC 3339 formatted
                          timestamp or a unix timestamp. If the value is a duration, it is used as the
                          offset from the current time. (default 0s)
      --profile string    The type of certificate to sign (cp-as|cp-ca) (default "cp-as")

SEE ALSO
~~~~~~~~

* :ref:`scion-pki certificate <scion-pki_certificate>` 	 - Manage certificates for the SCION control plane PKI.

