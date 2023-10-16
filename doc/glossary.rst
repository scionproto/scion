********
Glossary
********

.. glossary::

   AS
   Autonomous System

      An autonomous system is a computer network controlled by a single entity, typically an
      Internet-service provider or a larger organization like a university, participating in the
      Internet routing.
      In the traditional BGP-based Internet, ASes are assigned 32-bit autonomous system numbers (ASN).
      The AS identifiers in SCION are longer, 48-bit, and usually occur in combination with the
      identifier for a specific :term:`ISD` in which the AS is being identified.

      In SCION, the concept of ASes takes a more prominent role as it also serves as "locator" in
      the addressing of end hosts.

   BFD
   Bidirectional Forwarding Detection

      Bidirectional Forwarding Detection (BFD) is a network protocol that is used to
      detect faults between two forwarding engines connected by a link.
      See :rfc:`5880` and :rfc:`5881`.

      In SCION, BFD is used to determine the liveness of the link between two border routers
      and trigger :term:`SCMP` error messages.

   CA
   Certificate Authority

      An entity that signs and issues digital certificates, certifying the ownership of a public
      key by the named subject of the certificate.
      CAs are a part of a public key infrastructure, like the SCION :term:`Control-Plane PKI`.

   CP-PKI
   Control-Plane PKI

      The SCION Control-Plane Public Key Infrastructure (PKI) defines the certificate hierarchy that
      allows to tie cryptographic keys to SCION AS identifiers.
      This is the machinery that allows to authenticate SCION control-plane messages.

      See :doc:`/cryptography/index`.

   End Host
   Endpoint
      A SCION **end host** is a computer or other device connected to a computer network in a
      SCION AS, able to send and receive SCION traffic.

      In the `IRTF PANRG's vocabulary of path properties <https://datatracker.ietf.org/doc/draft-irtf-panrg-path-properties/>`_,
      **endpoints** are the start and end node of a path.
      An endpoint can be an end host, but it applies slightly more generically to any node which is
      the source or destination of SCION traffic, e.g. to a gateway.

      The terms "endpoint" and "end host" are used mostly interchangeably.
      End host is preferred where the focus is (physical or virtual) machines and the software
      running on them, and endpoint is used otherwise.

   Interface ID
      An interface ID is the AS-local identifier for an inter-domain link.

      The interface ID is an arbitrary 16-bit number between 1 and 65535,
      assigned without external coordination by the operator of the AS.

   ISD
   Isolation Domain

      An Isolation Domain (ISD) is a set of participating :term:`ASes <AS>`.
      ISDs can overlap, i.e. ASes can participate in multiple ISDs.

      An ISD represents a scope for :term:`CAs <CA>` in the :term:`Control-Plane PKI`;
      CAs can issue certificates exclusively to ASes in their ISD.

      At the same time Isolation Domains also serve as a local routing domain.
      Inside an isolation domain, links between ASes form a directed acyclic graph, allowing
      efficient path discovery.
      Only the core ASes (i.e. the ASes at the top(s) of this directed acyclic graph) need to
      participate in the less efficient inter-ISD path discovery.

      See :ref:`overview-isds`.

   Beacon
   PCB
   Path-Segment Construction Beacon

      Path-Segment Construction Beacons are control-plane messages that are propagated through a
      SCION network during the :ref:`path exploration ("beaconing") <control-plane-beaconing>` process.
      On their way, PCBs accumulate authenticated network topology information (on the granularity
      of :term:`ASes <AS>`).

   SCMP
   SCION Control Message Protocol

      The SCION analog to `ICMP <https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`_.

      A supporting protocol for the SCION dataplane. It is used by SCION routers or end hosts to
      send error messages and for diagnostics (ping and traceroute).

      See :doc:`/protocols/scmp` for more information.

   TRC
   Trust-Root Configuration

      Each :term:`ISD` has a separate trust-root configuration, specifying the core ASes acting as
      :term:`CAs <CA>`.

      See :doc:`/cryptography/trc`.
