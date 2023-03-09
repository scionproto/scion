The HTTP API is exposed by the :program:`router` application.
The IP address and port of the HTTP API is taken from the :option:`metrics.prometheus <common-conf-toml metrics.prometheus>` configuration
setting.

The HTTP API does not support user authentication or HTTPS. Applications will want to firewall
this port or bind to a loopback address.

The :program:`router` currently only supports the :ref:`common HTTP API <common-http-api>`.

.. TODO
   The router DOES appear to have a partially redundant OpenAPI as well!
