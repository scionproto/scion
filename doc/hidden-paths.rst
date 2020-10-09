************
Hidden Paths
************

This file documents the design for the hidden paths infrastructure.

Overview
========

Hidden path communication enables the hiding of specific path segments, i.e.
certain path segments are only available for authorized ASes. In the common
case, path segments are publicly available to any network entity. They are
fetched from the control service and used to construct forwarding paths. In a
hidden path communication setting, certain down-segments are not registered
publicly. Instead, they are registered at hidden segment service instances which
enforce access control, such that only authorized entities can fetch and use
these segments to create forwarding paths. Likewise, the corresponding
up-segment can be registered as hidden up-segment at the local hidden segment
service such that endhosts are aware that they are using hidden path
communication to leave the AS.

.. image:: fig/hidden_paths/HiddenPath.png

*Hidden Path communication scheme:*

#. *Owner* AS creates a hidden path group and shares the configuration
   out-of-band.

#. *Writer* ASes register down-segments at *Registry* ASes of their group.

#. *Reader* ASes query *Registry* ASes for hidden segments.

#. *Reader* ASes can communicate with *Writer* ASes based on hidden path segments.

Design
======

Hidden path group
-----------------

A hidden path group is defined as a group of ASes within which hidden path
information is shared. A hidden path group consists of:

- GroupID: Unique 64bit identification of the group:
  :math:`OwnerAS_{48bit}||GroupID_{16bit}`

- Version: A version indicating the version of the configuration

- Owner: AS ID of the owner of the hidden path group. The Owner AS is
  responsible for maintaining the hidden path group configuration and
  distributing it to all servers that require it. *(Access: Read/Write)*

- Writers: All ASes in the group which are allowed to register hidden paths
  *(Access: Read/Write)*

- Readers: All ASes in the group which are allowed to read hidden path
  information *(Access: Read)*

- Registries: All ASes in the group at which *Writers* register hidden paths
  *(Access: Read)*

The hidden path group configuration is shared amongst the members of the group
out-of-band. It is the group owner's responsibility to disseminate updated
versions to all members. An online way to initially share and update the hidden
path group configuration might be added in the future.

Example group configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Below is an example of a hidden path group configuration file
(``hp_group_ff00_0_110-69b5.json``):

.. code-block:: json

   {
       "group_id": "ff00:0:110-69b5",
       "version": 1,
       "owner": "1-ff00:0:110",
       "writers": [
           "1-ff00:0:111",
           "1-ff00:0:112"
       ],
       "readers": [
           "1-ff00:0:114"
       ],
       "registries": [
           "1-ff00:0:111",
           "1-ff00:0:113"
       ]
   }

Segment registration
--------------------

The segment registration needs to distinguish between segments to be registered
publicly and hidden. Additionally, a segment can be registered as up-segment
only or as down-segment only. These decisions are based on a policy defined in a
configuration file. For each segment, identified by its interface ID, the
following parameters can be defined:

- ``max_expiration``:  The time interval after which the segment becomes invalid

- ``reg_down``: Whether to register the segment as down-segment.

- ``reg_up``: Whether to register the segment as up-segment.

These parameters can be specified for *public* and for each hidden path group
individually. Segments not explicitly listed are either fully registered as
public up- and down-segments or not registered at all, depending on the
configured default action.

The beaconing module can be configured to not allow the registration of a
segment both as public and hidden.

Example registration configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Below is an example ``hp_policy.yml`` configuration. In ``hidden_path_groups``
all the hidden path groups available to the service are listed. Furthermore, the
configuration contains the segment registration policies in the
``segment_registration`` section. The file ``hp_policy.yml`` in turn is pointed
to by the ``cs.toml`` file by specifying the ``hidden_path_registration``
parameter.

.. code-block:: yaml

   ---
   hidden_path_groups:
     "ff00:0:110-69b5":
       config_file: testdata/hp_group_ff00_0_110-69b5.json
     "ffaa:0:222-abcd":
       config_file: testdata/hp_group_ffaa_0_222-abcd.json
   segment_registration:
     default_action: register
     hidden_and_public: true
     # Mapping from ingress interface to registration policy
     policies:
       2:
         public:
           register_up: true
           register_down: true
           max_expiration: 1h
         "ff00:0:110-69b5":
           register_up: true
           register_down: true
           max_expiration: 1h
         "ffaa:0:222-abcd":
           register_up: true
           register_down: true
           max_expiration: 1h
       3:
         public:
           register_up: true
           register_down: true
           max_expiration: 1h

The default action is set to ``register``, this means that all segments not
listed in this configuration are registered as public up- and down-segments with
default expiration. Note that the segment with interface ID 2 is both registered
as hidden and public. This is allowed by setting ``hidden_and_public`` to
``true``.

Hidden segment registration service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The hidden segment registration service needs to verify that the sender of the
segment is a writer in the hidden path group it tries to register.

Below is the gRPC definition of the service that accepts hidden segment
registrations.

.. code-block:: protobuf

   service HiddenSegmentRegistrationService {
       // HiddenSegmentRegistration registers hidden segments at the remote.
       rpc HiddenSegmentRegistration(HiddenSegmentRegistrationRequest) returns (HiddenSegmentRegistrationResponse) {}
   }

   message HiddenSegmentRegistrationRequest {
       message Segments {
           // List of path segments.
           repeated PathSegment segments = 1;
       }

       // Mapping from path segment type to path segments. The key is the integer
       // representation of the SegmentType enum.
       map<int32, Segments> segments = 1;

       // GroupID is the group ID to which these segments should be registered.
       uint64 group_id = 2;
   }

  message HiddenSegmentRegistrationResponse {}

Note that ``PathSegment`` and ``SegmentType`` are already defined by the normal
segment registration service and should be reused from there.

Path lookup
-----------

Hidden segment lookup service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The hidden segment lookup service can be queried for hidden segments to a given
destination. The request includes a set of hidden path group IDs and a
destination ISD-AS identifier. Upon receiving a request, the service must
validate the requester is allowed to access the requested hidden path groups.
For this, the service checks that for each requested group ID the requesting AS
has read access, i.e. is listed in the hidden path group.

Once validation is completed, the hidden segment lookup service can take one of
the following actions for each group ID in the request:

- lookup segments in the database for hidden path groups where the local AS is a
  *Registry* and thus the service is *authoritative*.
- *forward* the request to a hidden segment lookup service in an AS that is a
  *Registry* for the requested hidden path groups. Forwarding is only allowed if
  the request comes from within the AS, i.e. from a SCION daemon.

Note that multiple *forward* requests might be required depending on the hidden
path groups that are requested. To determine a small set of *Registry* ASes to
query for the required ``GroupID``'s the hidden paths lookup service should
partition the requested ``GroupID``'s into disjoint subsets, such that each
subset is covered by a single *Registry*. Note that a minimal set is not
strictly required since this is only an optimization.

The gRPC definition of the service is as follows:

.. code-block:: protobuf

   service HiddenSegmentLookupService {
       // HiddenSegments returns all segments that match the request.
       rpc HiddenSegments(HiddenSegmentsRequest) returns (HiddenSegmentsResponse) {}
   }

   message HiddenSegmentsRequest {
       // Hidden path group IDs for which a hidden segment is requested.
       repeated uint64 group_ids = 1;
       // The destination ISD-AS of the segment.
       uint64 dst_isd_as = 2;
   }

   message HiddenSegmentsResponse {
       message Segments {
           // List of path segments.
           repeated PathSegment segments = 1;
       }

       // Mapping from path segment type to path segments. The key is the integer
       // representation of the SegmentType enum.
       map<int32, Segments> segments = 1;
   }

SCION daemon
^^^^^^^^^^^^

Additional to up-, core- and down-segments, the daemon is responsible for
fetching hidden down-segments. The daemon is configured with the hidden path
group IDs it should query. Using the configured hidden path group IDs the daemon
queries the local hidden segment lookup service for the given destination. Once
the daemon has all segments collected it combines the segments to paths and returns the paths
to the requester.

Everything combined the path lookup looks as follows:

.. image:: fig/hidden_paths/PathLookup.png

Hidden segment service discovery
--------------------------------

Hidden segment services in remote ASes can be discovered via a hidden segment
service discovery. Similar to the gateway discovery an initial UDP roundtrip is
done to find the discovery service. The discovery service can then be queried
for hidden segment services. The reply of the discovery contains a list of
hidden segment lookup services and a list of hidden segment registration
services.

To make the information of what hidden segment services exist in an AS available
to the discovery service, the servers that run hidden segment services must
register in the topology file:

- Servers that run the hidden segment lookup service must be listed as
  ``hidden_segment_lookup_service``.

- Servers that run the hidden segment registration service must be listed as
  ``hidden_segment_registration_service``.

Note that having access control on the hidden segment discovery service is not
strictly required, since even if someone can get access to the enpoints, which
service hidden segment infrastructure, the services themselves must verify
that only authorized parties read or write hidden segment data.

Discovery service gRPC definition
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: protobuf

   service DiscoveryService {
       // Return the remote hidden segment services.
       rpc HiddenSegmentServices(HiddenSegmentServicesRequest) returns (HiddenSegmentServicesResponse) {}
   }

   message HiddenSegmentServicesRequest {}

   message HiddenSegmentServicesResponse {
       // The list of lookup services.
       repeated HiddenSegmentService lookup = 1;
       // The list of registration services.
       repeated HiddenSegmentService registration = 2;
   }

   message HiddenSegmentService {
       // The control address of this hidden segment service.
       string control_address = 1;
   }

Security
--------

Various operations in this design are security critical and require
client/server authentication:

#. For the creation of hidden path groups we assume that the chosen out-of-band
   mechanism is safe.

#. For segment registrations from a control server to the hidden path
   registration service we need to authenticate the AS of the registration
   service. This can be done using TLS based on AS certificates.

#. The SCION daemon querying paths from the local hidden path lookup service is
   secured by AS internal policies / PKIs.

#. For inter-AS hidden segment lookups, clients are authenticated using
   TLS client certificates based on the AS certificate.
