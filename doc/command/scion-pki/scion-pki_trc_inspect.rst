:orphan:

.. _scion-pki_trc_inspect:

scion-pki trc inspect
---------------------

Represent TRC in a human readable form

Synopsis
~~~~~~~~


'human' outputs the TRC contents in a human readable form.

The input file can either be a TRC payload, or a signed TRC.
The output can either be in yaml, or json.

By default, this command attempts to handle decoding errors gracefully. To
return an error if parts of a TRC fail to decode, enable the strict mode.


::

  scion-pki trc inspect [flags]

Examples
~~~~~~~~

::

    scion-pki trc human ISD1-B1-S1.pld.der
    scion-pki trc human ISD1-B1-S1.trc

Options
~~~~~~~

::

      --format string        Output format (yaml|json) (default "yaml")
  -h, --help                 help for inspect
      --predecessor string   Predecessor TRC (needed to display signature purpose)
      --strict               Enable strict decoding mode

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc <scion-pki_trc>` 	 - Manage TRCs for the SCION control plane PKI

