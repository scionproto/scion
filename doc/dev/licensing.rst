.. _licensing:

=========
Licensing
=========

Open Source License
===================

The SCION open-source implementation is software released under the `Apache License, Version 2.0 <https://github.com/scionproto/scion/blob/master/LICENSE>`_.

You may use, reproduce, and distribute the software in compliance with the License.

Intellectual Property
=====================

Anapaya Systems AG holds intellectual property (IP) and patents related to certain SCION technologies. In general, this open-source SCION implementation does not utilize these patents.

To provide even further reassurance and to foster innovation within the open-source community, Anapaya has also issued a formal open-source patent pledge.

For full details regarding the terms of the pledge and the specific patents covered, and commercial licensing, please read the `Anapaya Open Source Patent Pledge <https://learn.anapaya.net/docs/resources/patent-pledge/>`_.

FAQ
===

Can I use this implementation because of the patents?
-----------------------------------------------------

Yes, because this open-source SCION implementation does not utilize these patents.
Regardless, users of the open-source project are fully protected by the provisions of the Apache 2.0 License itself. Specifically, **Section 3** of the license provides an explicit patent grant from all contributors. Because Anapaya is a contributor to the open-source project, it grants users a perpetual, worldwide, non-exclusive, royalty-free patent license for any patent claims necessarily infringed by its contributions to the codebase. 

What are the patents about?
---------------------------

Patents overview:

.. list-table::
   :widths: 20 35 45
   :header-rows: 1

   * - Patent Family
     - Title
     - Description
   * - EP3941006B1, US20220021599A1
     - System and method for carrying and optimizing internet traffic over a source-selected path routing network
     - The patent describes a system to embed a SCION Internet in the BGP-based Internet as a single BGP AS. Furthermore, it describes how this embedding can be used to optimize network traffic based on source-based path selection.
   * - EP3756317B1, US11240140B2, CN111771359B
     - Method and system for interfacing communication networks
     - The patent describes a system to discover and select remote SCION-IP gateways (SIGs) and optimize SCION path selection based on a variety of metrics to a remote SIG.
   * - EP3941003A1, US11362932B2
     - Achieving highly available autonomous systems (as) in a source-selected path routing network
     - The patent describes an implementation of a highly available SCION AS control-plane relying on sharding, gossiping, and eventual consistency.