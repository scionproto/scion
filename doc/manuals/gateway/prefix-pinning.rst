When a SCION Gateway sends data to a remote SCION Gateway, it does so based
on the policies that are configured locally and the prefixes it learns from
the remote gateway. When multiple remote gateways are available, the choice
of gateway and path is completely in the hands of the sending AS.

However, in some scenarios the remote AS might be composed of multiple data
centers, and might want to avoid traffic between the data centers. To do this
it can use a feature called Prefix pinning, which allows a remote AS to hint
at how traffic should be sent towards it. In this section we outline when
Gateway pinning is relevant, and how to configure it.

Refer to the topology below. New Zealand is the local AS, and it contains one
IPv4 network: ``10.0.2.0/24``. This network wants to communicate with two
networks in the Australia AS, ``192.168.1.0/24`` and ``192.168.2.0/24``. The
networks are reachable through either the Perth Router (Interface ID 101) or
the Melbourne Router (Interface ID 201), and then, depending on the
destination network, through either the Perth Gateway or Melbourne Gateway.

.. image:: gateway/prefix_pinning.png

It is possible for traffic to flow from the Perth Router to the Melbourne
Gateway. This can happen if the New Zealand gateway chooses to encapsulate
traffic for the Melbourne gateway but chooses a path going through the Perth
router.

The networking administrators of the Australia AS want to prohibit this
behavior because it would lead to increased latency and an inefficient use of
inter-DC bandwidth. Instead, ``192.168.1.0/24`` should only be reachable
through the Perth Router and Gateway, and ``192.168.2.0/24`` should only be
reachable through the Melbourne Router and Gateway.

We'll first look at how the basic configuration for dynamic prefix discovery
for the Perth and Melbourne gateways would look like, and then see why it is
not sufficient to provide the connectivity constraints the Australia AS
administrators want.

To configure dynamic prefix discovery, Australia configures its gateways with
the following traffic policies:

.. code-block:: text

   # Perth
   advertise 2-ff00:0:2 1-ff00:0:1 192.168.1.0/24
   accept           0-0        0-0      0.0.0.0/0

   # Melbourne
   advertise 2-ff00:0:2 1-ff00:0:1 192.168.2.0/24
   accept           0-0        0-0      0.0.0.0/0


This will have the gateways advertise the two internal networks in Australia,
and the New Zealand gateway will thus learn the prefixes and be able to route
to them. For completeness, the New Zealand gateway might have the following
configuration:

.. code-block:: text

   # New Zealand
   advertise 1-ff00:0:1 2-ff00:0:2 10.0.2.0/24
   accept           0-0        0-0   0.0.0.0/0

Assuming routing inside the two ASes is configured correctly, hosts in
``10.0.2.0/24`` should now be able to ping hosts in ``192.168.1.0/24`` and
``192.168.2.0/24``.

However, when New Zealand chooses paths for reaching the gateways in
Australia, it does so independently of the remote gateways. This is because
the internal structure of the Australia AS is hidden from New Zealand, so it
cannot make assumptions about what paths would be more appropriate for each
gateway. In total, there are four possible combinations:

#. Perth Router (Interface ID 101) to Perth Gateway (for destination ``192.168.1.1``).
#. Perth Router (Interface ID 101) to Melbourne Gateway (for destination ``192.168.2.1``).
#. Melbourne Router (Interface ID 201) to Perth Gateway (for destination ``192.168.1.1``).
#. Melbourne Router (Interface ID 201) to Melbourne Gateway (for destination ``192.168.2.1``).

For Australia to recommend that New Zealand use only options 1 and 4, it
needs an additional config.

Path pinning is a Discovery Service setting that informs the Discovery Service to
hint to other ASes which SCION Interfaces should be used to reach a gateway.
The setting is configured via the topology file.

In this scenario, Australia can configure the topology file as follows:

.. code-block:: json

   {
     "sigs": {
       "perth": {
         "ctrl_addr": "...omitted...",
         "data_addr": "...omitted...",
         "allow_interfaces": [
           101
         ]
       },
       "melbourne": {
         "ctrl_addr": "...omitted...",
         "data_addr": "...omitted...",
         "allow_interfaces": [
           201
         ]
       }
     }
   }

Due to the additional ``allow_interfaces`` setting, the Discovery Service in
the Australia AS will announce that the respective gateways should be
reachable only through the specified interface. Note that this is only a
hint. In the end, the New Zealand AS can choose to ignore this setting, and
still send data to the Melbourne network via the Perth router. However,
Anapaya software will respect the hint.

Multiple interfaces can be specified in ``allow_interfaces``, and the same
interface can be present under multiple gateways.
