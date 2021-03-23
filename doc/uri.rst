**************************
SCION Address URI encoding
**************************

Certain libraries and applications rely on addresses encoded in an URI format.
This document defines a URI syntax for encoding SCION addresses.

Schemes
=======

The SCION control plane uses two mechanisms to establish a QUIC/SCION
connection. If the client knows the exact address the server is listening for
QUIC/SCION connections on, it can directly establish the connection.

For cases where the QUIC port cannot be known before hand, e.g., anycast to an
svc address, the server will deploy a redirect endpoint. This endpoint runs
on UDP/SCION, and redirects requests to the QUIC endpoint.

To distinguish the two cases, we employ two different schemes.

scion
-----

The ``scion`` scheme indicates, that the client should directly dial a
QUIC/SCION connection to the specified authority.

The scheme syntax is defined as follows:

.. code-block:: text

   scion://host[:port][/path]

Example:

.. code-block:: text

   scion://[1-ff00:0:110,192.0.2.1]:30652
   scion://[1-ff00:0:110,2001:DB8::1]:30652

scion+udp
---------

The ``scion+udp`` scheme indicates, that the client should attempt to query a
redirect over UDP/SCION, and establish a QUIC/SCION connection on the resolved
address.

The scheme syntax is defined as follows:

.. code-block:: text

   scion+udp://host[:port][/path]

Examples:

.. code-block:: text

   scion+udp://[1-ff00:0:110,2]
   scion+udp://[1-ff00:0:110,192.0.2.1]:30252
   scion+udp://[1-ff00:0:110,2001:DB8::1]:30252

Extensions to `RFC 3986 <https://tools.ietf.org/html/rfc3986>`_
===============================================================

`RFC 3986 <https://tools.ietf.org/html/rfc3986>`_ defines a host with the
following ABNF:

.. code-block:: py

   host          = IP-literal / IPv4address / reg-name
   IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
   IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

We extend the definition of ``IP-literal`` with a ``SCIONAddress``:

.. code-block:: py

   IP-literal    = "[" ( SCIONAddress / IPv6address / IPvFuture  ) "]"
   SCIONAddress  = ISD "-" AS "," ( IPv4address / IPv6address / SvcAddress )
   ISD           = 1*DIGIT
   AS            = (1*4HEXDIG ":" 1*4HEXDIG ":" 1*4HEXDIG) / 1*DIGIT
   SvcAddress    = dec-octet

Some examples of a valid extended ``IP-literal``:

  - ``[1-ff00:0:110,192.0.2.1]``
  - ``[1-ff00:0:110,2001:DB8::1]``
  - ``[1-64496,2001:DB8::1]``
  - ``[1-64496,2]``
  - ``[2001:DB8::1]``

See `RFC 3986, Appendix A <https://tools.ietf.org/html/rfc3986#appendix-A>`_ for
all the rules that are not defined here.

Considered alternatives
-----------------------

We chose to extend the definition of ``IP-literal`` similar to `RFC 6874
<https://tools.ietf.org/html/rfc6874>`_. We considered the following
alternatives in the process.

Using IPvFuture
^^^^^^^^^^^^^^^

Instead of extending the ``IP-literal`` definition, we could utilize the
``IPvFuture`` and allocate a version number to SCION. However, SCION unaware
applications will fail to parse URIs, since they do not know the version number.
Without obvious benefit, this would introduce a constant and redundant prefix
that needs to be included in every URI.

Encode ISD-AS and IP in ``reg-name``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We could encode the ISD-AS and IP address in the host as a ``reg-name``. The
drawback is, that neither ``:``, nor ``[]`` are valid characters in
``reg-name``. They either need to be percent encoded, or replaced with a
different character. Both of these options are suboptimal for readability.

Encode address as path
^^^^^^^^^^^^^^^^^^^^^^

We could encode a SCION address as an absolute path. For example:
``scion:/1-ff00:0:110/2001:DB8::1/30652``. The drawback is, that this notation
is very unfamiliar. We loose the concept of what is the authority and what is
the path.
