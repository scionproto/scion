:orphan:

.. _scion-pki_certificate_validate:

scion-pki certificate validate
------------------------------

Validate a SCION cert according to its type

Synopsis
~~~~~~~~


'validate' checks if the certificate is valid and of the specified type.

In case the 'any' type is specified, this command attempts to identify what type
a certificate is and validates it accordingly. The identified type is stated in
the output.

By default, the command does not check that the certificate is in its validity
period. This can be enabled by specifying the \--check-time flag.


::

  scion-pki certificate validate [flags]

Examples
~~~~~~~~

::

    scion-pki certificate validate --type cp-root /tmp/certs/cp-root.crt
    scion-pki certificate validate --type any /tmp/certs/cp-root.crt

Options
~~~~~~~

::

      --check-time          Check that the certificate covers the current time.
      --current-time time   The time that needs to be covered by the certificate.
                            Can either be a timestamp or an offset.
                            
                            If the value is a timestamp, it is expected to either be an RFC 3339 formatted
                            timestamp or a unix timestamp. If the value is a duration, it is used as the
                            offset from the current time. (default 0s)
  -h, --help                help for validate
      --type string         type of cert (any|chain|cp-as|cp-ca|cp-root|regular-voting|sensitive-voting) (required)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki certificate <scion-pki_certificate>` 	 - Manage certificates for the SCION control plane PKI.

