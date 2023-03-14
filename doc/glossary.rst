********
Glossary
********

.. glossary::

   BFD
   Bidirectional Forwarding Detection

      Bidirectional Forwarding Detection (BFD) is a network protocol that is used to
      detect faults between two forwarding engines connected by a link.
      See :rfc:`5880` and :rfc:`5881`.

      In SCION, BFD is used to determine the liveness of the link between two border routers
      and trigger :term:`SCMP` error messages

   SCMP
   SCION Control Message Protocol

      The SCION analog to `ICMP <https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`_.

      A supporting protocol for the SCION dataplane. It is used by SCION routers or end hosts to
      send error messages and for diagnostics (ping and traceroute).

      See :doc:`/protocols/scmp` for more information.

