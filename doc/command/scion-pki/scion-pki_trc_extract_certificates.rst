:orphan:

.. _scion-pki_trc_extract_certificates:

scion-pki trc extract certificates
----------------------------------

Extract the bundled certificates

Synopsis
~~~~~~~~


'certificates' extracts the certificates into a bundeld PEM file.

::

  scion-pki trc extract certificates [flags]

Examples
~~~~~~~~

::

    scion-pki trc extract certificates -o bundle.pem input.trc

Options
~~~~~~~

::

  -h, --help         help for certificates
  -o, --out string   Output file (required)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc extract <scion-pki_trc_extract>` 	 - Extract parts of a signed TRC

