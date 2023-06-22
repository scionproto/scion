:orphan:

.. _scion-pki_trc_format:

scion-pki trc format
--------------------

Reformat a TRC or TRC payload

Synopsis
~~~~~~~~


'format' prints the TRC or TRC payload in a different format.

The PEM type for a TRC is 'TRC', and for a TRC payload it is 'TRC PAYLOAD'.

By default, the output is PEM encoded. DER format can be requested by providing
'der' in the \--format flag. When selecting DER output, ensure stdout is
redirected to a file because the raw characters might mess up the terminal.


::

  scion-pki trc format [flags] <trc-file>

Examples
~~~~~~~~

::

    scion-pki trc format ISD1-B1-S1.trc.der
    scion-pki trc --format der ISD1-B1-S2.pld --out ISD1-B1-S2.pld.der

Options
~~~~~~~

::

      --force           Force overwriting existing output file
      --format string   The Output format (der|pem) (default "pem")
  -h, --help            help for format
      --out string      The path to write the transformation TRC or TRC payload

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc <scion-pki_trc>` 	 - Manage TRCs for the SCION control plane PKI

