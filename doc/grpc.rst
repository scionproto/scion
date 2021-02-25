*********************************
Teaching gRPC some path-awareness
*********************************

The SCION control plane uses gRPC to have a reliable RPC mechanism. gRPC is
very flexible, and employs powerful concepts that we can utilize to make
our RPC stack path aware.

gRPC Primer
===========

The following image from the `gRPC Blog
<https://grpc.io/blog/grpc-on-http2/#grpc-semantics>`_ summarizes the semantics
around connections in gRPC quite well.

.. image:: fig/grpc/grpc_on_http2_mapping.png
  :width: 400
  :alt: http2 mapping

The terminology in go library is slightly different:

- A client dials a ``ClientConn`` to a target service (instead of a Channel).
- The ``ClientConn`` has one or multiple HTTP/2 connections, called ``SubConn``
  (instead of a Conn).

The go gRPC stack consists of multiple components that interact with each other
to make an RPC happen.

When a ``ClientConn`` is dialed, gRPC creates a ``Resolver`` and ``Balancer``
instance specific to this ``ClientConn``.

The resolver is responsible for resolving a string target that is passed to
``grpc.Dial`` to one or more addresses that can be used for establishing a
``ClientConn``. The syntax for the target is described here: `gRPC Name
Resolution <https://github.com/grpc/grpc/blob/master/doc/naming.md>`_.

The balancer has two functions. It manages what ``SubConns`` should be opened or
closed by the ``ClientConn``. When RPCs are scheduled on a ``ClientConn``, the
balancer picks what ``SubConn`` the RPC should use.

gRPC will handle the connection establishment and monitoring for each
``SubConn``. HTTP/2 has a mechanism in the protocol to health check the
connection. This will show L4 connection healthiness, but not at the application
layer. (L7 health checks can optionally be enabled.) The ``SubConns`` are dialed
with with the target provided by the balancer, that were original resolved by the
resolver. The dialer can be customized.

The ``ClientConn`` acts as a middle-man between resolver and balancer. Each of
them have their own view of what a ``ClientConn`` provides. See
`resolver.ClientConn
<https://pkg.go.dev/google.golang.org/grpc/resolver?tab=doc#ClientConn>`_ and
`balancer.ClientConn
<https://pkg.go.dev/google.golang.org/grpc/balancer?tab=doc#ClientConn>`_.

The `Dialer <https://pkg.go.dev/google.golang.org/grpc?tab=doc#WithContextDialer>`_
simply takes a string as its input.

Default behavior
----------------

By default, gRPC uses the following combination:

- Resolver: DNS resolver that resolves host names to IP addresses.
- Balancer: Pick first balancer, that always picks the first address out of the
  list that was provided by the resolver.
- Dialer: `net.Dialer` with `tcp` from stdlib.

Teaching an old dog new tricks |grpc|
=====================================

.. |grpc| image:: fig/grpc/grpc.png
   :width: 30

The way gRPC splits the responsibilities in these different components is very
powerful, as it allows us to plug in path awareness into the gRPC stack.

At a high-level, we can do the following:

- Plug a resolver that can take a SCION address and resolve paths. The resolver
  attaches information about the path to `resolver.Address
  <https://pkg.go.dev/google.golang.org/grpc/resolver?tab=doc#Address>`_.
- Plug a balancer that picks healthy ``SubConns`` for each RPC.
- Plug a dialer that can dial QUIC/SCION to specific targets provided by the
  resolver.

In order to profit from this connection management, we need to have long-lived
connections between control plane entities. This can be abstracted in some
kind of connection manager.

Resolver
--------

There are two things that need to be resolved when considering SCION control
plane interactions. First, we need paths to be resolved in order to contact
remote ASes. Second, we need to resolve the QUIC address if we are handed an svc
address.

For the first iteration, it makes sense to restrict ourselves to resolving
paths. Redirecting from svc to an actual address can still be done by the
dialer. In fact, it will be more reliable for remote ASes with multiple control
servers until we have a service lookup RPC.

The resolver will resolve paths for addresses with the ``scion://`` and
``scion+udp://`` scheme.

Since the dialer only takes a string as the target, we need to share state
between the resolver and the dialer in form of a path registry. The path
registry is a mapping from path identifier to the actual path object.
The resolver will encode the path choice in the target address.

For example, the client wants to dial ``scion+udp://[1-ff00:0:110,2]`` where
``2`` indicates the control service. The resolver will resolve paths, create IDs
for each path it resolves, and register them with the path registry. The
resolver then returns resolved addresses ``scion+udp://<id>@[1-ff00:0:110,2]``
(format up for discussion).

Dialer
------

The dialer will establish a QUIC/SCION connection to the target. The path is
retrieved from the shared state between the dialer and the resolver.

Balancer
--------

For the first iteration, the balancer does not need to be SCION path aware. The
default round robin balancer should suffice. It will pick healthy connections
in a round robin fashion.

At a later stage, we can plug our own balancer that takes path properties into
account. Or a balancer that prefers to stick with the same ``SubConn`` until it
is no longer healthy.

ConnManager
-----------

To profit from gRPC monitoring the connection health, connections must be long
lived. The ``ConnManager`` will be invoked to establish ``ClientConns``. It will
take care of ``ClientConn`` management. If there is already a ``ClientConn`` to
a requested target, the ``ConnManager`` simply returns a reference to that,
instead of establishing a new one. It will also need to run garbage collection
to close ``ClientConns`` that have not been actively used for some amount of
time.

In the code base, we already plug a ``Dialer`` interface everywhere. The
ConnManager can be hidden behind this interface. We also need to abstract the
returned ``ClientConn``. Then, we can wrap the ``grpc.ClientConn`` and use
the ``Close`` method for reference tracking.

Things to investigate
=====================

#. How often does the resolution trigger? Does it ever trigger if everything is
   fine?
