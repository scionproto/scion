***************
Control Service
***************

Port table
==========

+---------------------------+----------------+--------+-----------------------------+
|    Description            | Transport      | Port   | Application protocol        |
+---------------------------+----------------+--------+-----------------------------+
| Service resolution        | UDP/SCION      | 30252  | Resolution protobufs        |
+---------------------------+----------------+--------+-----------------------------+
| Control-plane (inter-AS)  | UDP/SCION      | random | QUIC + gRPC with HTTP/2     |
|                           |                |        |                             |
| Discovery API             |                |        |                             |
+---------------------------+----------------+--------+-----------------------------+
| Control-plane (intra-AS)  | TCP            | 30252  | gRPC with HTTP/2            |
|                           |                |        |                             |
| Health API                |                |        |                             |
+---------------------------+----------------+--------+-----------------------------+
| Monitoring                | TCP            | 30452  | HTTP/2                      |
+---------------------------+----------------+--------+-----------------------------+

Metrics
=======

.. warning::

   The list of control service metrics is incomplete.

Renewal requests
----------------

**Name**: ``renewal_received_requests_total``

**Type**: Counter

**Description**: Total number of certificate renewal requests served. Only for
control services with CA functionality enabled.

**Labels**: ``result``.

Renewal requests per handler type
---------------------------------

**Name**: ``renewal_handled_requests_total``

**Type**: Counter

**Description**: Total number of renewal requests served by each handler type
(legacy, in-process, delegating).

**Labels**: ``type`` and ``result``.

.. note::
   The sum of all ``renewal_handled_requests_total`` is not necessarily equal to
   the sum of all ``renewal_received_requests_total``. This is because
   ``renewal_received_requests_total`` counts all incoming request and
   ``renewal_handled_requests_total`` only counts requests that could have been
   parsed and delegated to a handler.

Renewal request registered handlers
-----------------------------------

**Name**: ``renewal_registered_handlers``

**Type**: Gauge

**Description**: Exposes which handler type (legacy, in-process, delegating) is
registered.

**Labels**: ``type``.

HTTP API
========

The HTTP API is exposed by the ``control`` application on the IP address and port of the ``metrics.prometheus``
configuration setting.

The HTTP API does not support user authentication or HTTPS. Applications will want to firewall
this port or bind to a loopback address.

In addition to the :ref:`common HTTP API <common-http-api>`, the ``control``
application supports the following API calls:

- ``/topology`` (**EXPERIMENTAL**)

  - Method **GET**. Prints a JSON representation of current topology state, displayed in
    a format that is similar to the topology file. Note that there are slight differences
    between the output format and the topology file format, which means the output cannot
    be copy/pasted and used as a topology file.

- ``/signer`` (**EXPERIMENTAL**)

  - Method **GET**. Prints JSON data about the Subject Key (i.e., the key used by the
    application to sign messages) and the TRC in use, in addition to other miscellaneous
    data that is relevant for signing. Private keys are not printed. Example output:

    .. code-block:: json

       {
         "subject": {
           "isd_as": "1-ff00:0:110"
         },
         "subject_key_id": "21 36 9B 82 D3 B9 90 58 16 D0 90 C0 15 66 C3 DC 0E 46 A5 9B",
         "expiration": "2021-09-28T13:19:16Z",
         "trc_id": {
           "isd": 1,
           "base_number": 1,
           "serial_number": 1
         },
         "chain_validity": {
           "not_before": "2020-09-28T13:19:16Z",
           "not_after": "2021-09-28T13:19:16Z"
         },
         "in_grace_period": false
       }

For ASes that operate as CAs, the following API calls are also exposed:

- ``/ca`` (**EXPERIMENTAL**)

  - Method **GET**. Prints JSON data about the Subject Key (i.e., the key used by the CA
    to sign certificates) and the CA policy. Example output:

    .. code-block:: json

       {
         "subject": {
           "isd_as": "1-ff00:0:110"
         },
         "subject_key_id": "8C 5A 07 FF 83 F7 C8 69 0A 28 01 4F CF 0F BF AB FF D5 E6 FF",
         "policy": {
           "chain_lifetime": "72h0m0s"
         },
         "cert_validity": {
           "not_before": "2020-09-28T13:19:16Z",
           "not_after": "2022-09-28T13:19:16Z"
         }
       }


