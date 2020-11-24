**********
Dispatcher
**********

Port table
==========

+---------------------------+----------------+--------+-----------------------------+
|    Description            | Transport      | Port   | Application protocol        |
+---------------------------+----------------+--------+-----------------------------+
| Underlay data-plane       | UDP            | 30041  | none                        |
+---------------------------+----------------+--------+-----------------------------+
| Monitoring                | TCP            | 30441  | HTTP/2                      |
+---------------------------+----------------+--------+-----------------------------+


HTTP API
========

The HTTP API is exposed by the ``dispatcher`` on the IP address and port of the ``metrics.prometheus``
configuration setting.

The HTTP API does not support user authentication or HTTPS. Applications will want to firewall
this port or bind to a loopback address.

The ``dispatcher`` currently only supports the :ref:`common HTTP API <common-http-api>`.
