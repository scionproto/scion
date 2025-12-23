:orphan:

.. _scion-pki_trc_extract_certificates:

scion-pki trc extract certificates
----------------------------------

Extract the bundled certificates

Synopsis
~~~~~~~~


'certificates' extracts the certificates into a bundled PEM file.

::

  scion-pki trc extract certificates [flags]

Examples
~~~~~~~~

::

    scion-pki trc extract certificates -o bundle.pem input.trc

Options
~~~~~~~

::

  -h, --help                     help for certificates
  -o, --out string               Output file (optional)
      --subject.isd-as strings   Filter certificates by ISD-AS of the subject (e.g., 1-ff00:0:110)
      --type strings             Filter certificates by type (any|cp-as|cp-ca|cp-root|regular-voting|sensitive-voting)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc extract <scion-pki_trc_extract>` 	 - Extract parts of a signed TRC

