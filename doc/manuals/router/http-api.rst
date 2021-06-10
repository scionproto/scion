The HTTP API is exposed by the ``posix-router`` and the ``router`` control-plane application.
The IP address and port of the HTTP API is taken from the ``metrics.prometheus`` configuration
setting.

The HTTP API does not support user authentication or HTTPS. Applications will want to firewall
this port or bind to a loopback address.

The ``router`` and ``posix-router`` currently only support the :ref:`common HTTP API <common-http-api>`.
