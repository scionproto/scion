
.. warning::

   The list of control service metrics is incomplete.

Renewal
-------

Renewal requests
^^^^^^^^^^^^^^^^

**Name**: ``renewal_received_requests_total``

**Type**: Counter

**Description**: Total number of certificate renewal requests served. Only for
control services with CA functionality enabled.

**Labels**: ``result``.

Renewal requests per handler type
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Name**: ``renewal_registered_handlers``

**Type**: Gauge

**Description**: Exposes which handler type (legacy, in-process, delegating) is
registered.

**Labels**: ``type``.

TRC local filesystem writes
^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Name**: ``trustengine_trc_file_writes_total``

**Type**: Counter

**Description**: Total number of TRC local filesystem write results. A result
can be one of (ok_success, err_write, err_stat).

**Labels**: ``result``.
