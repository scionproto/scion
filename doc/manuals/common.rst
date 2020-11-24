***************
Common settings
***************

.. _common-http-api:

HTTP API
========

**Known issue**. If an unknown route is accessed (e.g., ``/this-does-not-exist``), the HTTP
reply will respond as if the ``/`` route were used and print an HTML page with links to
all exposed APIs. This response will have a 200 (OK) HTTP Status Code.

The following APIs are exposed by most applications:

- ``/``: (**EXPERIMENTAL**)
  - Method **GET**. Returns an HTML page containing links to exposed APIs.

- ``/config``: (**EXPERIMENTAL**)

  - Method **GET**. Prints the TOML representation of the config the application
    is currently using.

- ``/info``: (**EXPERIMENTAL**)

  - Method **GET**. Prints a plaintext representation of general information about
    the application. Amongst others, the information includes version,
    process ID, and user/group IDs.

- ``/log/level``: (**EXPERIMENTAL**)

  - Method **GET**: Returns the current logging level, in JSON.
  - Method **POST**: Sets the current logging level. Expects a JSON input. For example, to
    set the logging level to ``debug`` run:

    .. code-block:: bash

       curl -X PUT "http://172.20.1.3:30442/log/level" -H "Content-Type: application/json" -d "{\"level\":\"debug\"}"

- ``/metrics``:

  - Method **GET**: Returns the Prometheus metrics exposed by the application.
