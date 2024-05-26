:orphan:

.. _scion_address:

scion address
-------------

Show (one of) this host's SCION address(es)

Synopsis
~~~~~~~~


'address' show address information about this SCION host.

This command returns the relevant SCION address information for this host.

Currently, this returns a sensible but arbitrary local address. In the general
case, the host could have multiple SCION addresses.


::

  scion address [flags]

Examples
~~~~~~~~

::

    scion address

Options
~~~~~~~

::

  -h, --help            help for address
      --isd-as isd-as   The local ISD-AS to use. (default 0-0)
      --json            Write the output as machine readable json
  -l, --local ip        Local IP address to listen on. (default invalid IP)
      --sciond string   SCION Daemon address. (default "127.0.0.1:30255")

SEE ALSO
~~~~~~~~

* :ref:`scion <scion>` 	 - SCION networking utilities.

