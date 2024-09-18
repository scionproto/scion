:orphan:

.. _scion-pki_trc_payload_dummy:

scion-pki trc payload dummy
---------------------------

Generate dummy TRC payload

Synopsis
~~~~~~~~


'dummy' creates a dummy TRC payload.

The output of this command can be used to test that you have access to the necessary
cryptographic material. This is especially useful when preparing for a TRC signing
ceremony.


::

  scion-pki trc payload dummy [flags]

Options
~~~~~~~

::

      --format string   Output format (der|pem) (default "pem")
  -h, --help            help for dummy

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc payload <scion-pki_trc_payload>` 	 - Generate new TRC payload

