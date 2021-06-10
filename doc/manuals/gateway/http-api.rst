The HTTP API is exposed by the ``gateway`` on the IP address and port of the ``metrics.prometheus``
configuration setting.

The HTTP API does not support user authentication or HTTPS. Applications will want to firewall
this port or bind to a loopback address.

In addition to the :ref:`common HTTP API <common-http-api>`, the ``gateway`` supports the following API calls:

- ``/status`` (**EXPERIMENTAL**)

  - Method **GET**. Prints a text description of the operating state of the Gateway. This includes the
    list of remote AS numbers, the sessions that exist, what networks are in the
    routing table. For example, the description might look like the following (note that formatting
    and contents might change between releases):

    .. code-block:: text

       ISD-AS 1-ff00:0:111
         SESSION 0, POLICY_ID 0, REMOTE: 172.20.5.6:30856, HEALTHY true
           PATHS:
             STATE REVOKED LATENCY JITTER DROPRATE        PATH
             -->   false      0.47   0.59     0.00        Hops: [1-ff00:0:110 1>1 1-ff00:0:111] MTU: 1472 NextHop: 172.20.4.3:30042

       ISD-AS 1-ff00:0:112
         SESSION 1, POLICY_ID 0, REMOTE: 172.20.6.6:30856, HEALTHY true
           PATHS:
             STATE REVOKED LATENCY JITTER DROPRATE        PATH
             -->   false      0.63   0.74     0.00        Hops: [1-ff00:0:110 2>1 1-ff00:0:112] MTU: 1472 NextHop: 172.20.4.5:30042

       ISD-AS 1-ff00:0:113
         SESSION 2, POLICY_ID 0, REMOTE: 172.20.7.6:30856, HEALTHY true
           PATHS:
             STATE REVOKED LATENCY JITTER DROPRATE        PATH
             -->   false      0.67   0.51     0.00        Hops: [1-ff00:0:110 1>1 1-ff00:0:111 2>1 1-ff00:0:113] MTU: 1472 NextHop: 172.20.4.3:30042
                   false      0.65   0.79     0.00        Hops: [1-ff00:0:110 2>1 1-ff00:0:112 2>2 1-ff00:0:113] MTU: 1472 NextHop: 172.20.4.5:30042


       ROUTING TABLE:
       172.20.5.0/24 index: 2
         condition: BOOL=true
         session: {ID: 0, path: Hops: [1-ff00:0:110 1>1 1-ff00:0:111] MTU: 1472 NextHop: 172.20.4.3:30042}
       172.20.6.0/24 index: 3
         condition: BOOL=true
         session: {ID: 1, path: Hops: [1-ff00:0:110 2>1 1-ff00:0:112] MTU: 1472 NextHop: 172.20.4.5:30042}
       172.20.7.0/24 index: 1
         condition: BOOL=true
         session: {ID: 2, path: Hops: [1-ff00:0:110 1>1 1-ff00:0:111 2>1 1-ff00:0:113] MTU: 1472 NextHop: 172.20.4.3:30042}

- ``/engine`` (**EXPERIMENTAL**)

  - Method **GET**. Prints a text description of the full state of the forwarding engine of
    the Gateway. This includes session health, available paths, session configs, the
    control-plane routing and the data-plane routing table.

- ``/sessionconfigurator`` (**EXPERIMENTAL**)

  - Method **GET**. Prints a text description of the last input and output of the session
    configurator.

- ``/ip-routing/policy`` (**EXPERIMENTAL**)

  - Method **GET**. Prints the current routing policy.
  - Method **PUT**. Updates the current routing policy. This can be used instead of
    forcing a reload from disk via ``SIGHUP``. Only the routing policy is reloaded, and
    the update only affects the in-memory state of the gateway (in other words, the
    gateway does not write the configuration it has received to disk, so a restart will
    cause the changes to be overwritten by whatever is on disk).

- ``/configversion`` (**EXPERIMENTAL**)

  - Method **GET**. Prints the version number of the traffic policy configuration file.
