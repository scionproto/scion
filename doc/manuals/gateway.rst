*******
Gateway
*******

Nomenclature
============

.. include:: ./gateway/nomenclature.rst

Port table
==========

.. include:: ./gateway/port-table.rst

Metrics
=======

.. include:: ./gateway/metrics.rst

HTTP API
========

.. include:: ./gateway/http-api.rst

Routing Policy File
===================

.. include:: ./gateway/routing-policy.rst

Network prefix pinning
======================

.. include:: ./gateway/prefix-pinning.rst

Configuration
=============

In addition to the :ref:`common .toml configuration options <common-conf-toml>`, the gateway service
considers the following options.

.. object:: rpc

   .. option:: rpc.client_protocol = "grpc"|"connectrpc"|"all" (Default = "all")

      The rpc protocols that should be attempted when invoking the :program:`control` service.

   .. option:: rpc.server_protocol = "grpc"|"connectrpc"|"all" (Default = "all")

      The rpc protocols that should be supported by the :program:`gateway` service.
