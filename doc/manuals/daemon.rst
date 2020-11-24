******
Daemon
******

Port table
==========

+---------------------------+----------------+--------+-----------------------------+
|    Description            | Transport      | Port   | Application protocol        |
+---------------------------+----------------+--------+-----------------------------+
| Daemon API                | TCP            | 30255  | gRPC with HTTP/2            |
+---------------------------+----------------+--------+-----------------------------+
| Monitoring                | TCP            | 30455  | HTTP/2                      |
+---------------------------+----------------+--------+-----------------------------+


HTTP API
========

The HTTP API is exposed by the ``daemon`` on the IP address and port of the ``metrics.prometheus``
configuration setting.

The HTTP API does not support user authentication or HTTPS. Applications will want to firewall
this port or bind to a loopback address.

In addition to the :ref:`common HTTP API <common-http-api>`, the ``daemon`` supports the following API calls:

- ``/topology`` (**EXPERIMENTAL**)

  - Method **GET**. Prints a JSON representation of current topology state, displayed in
    a format that is similar to the topology file. Note that there are slight differences
    between the output format and the topology file format, which means the output cannot
    be copy/pasted and used as a topology file.
