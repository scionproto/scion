## SCION IP Gateway

Current version is a barebone proof of concept for the SIG.

### Host configuration

Enable routing:

```
  echo 1 > /proc/sys/net/ipv4/ip_forward
```

Disable Reverse Path Filtering:

```
  echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
```

### Testing

Run the SIG as root:

```
sudo sig -config sig.config -sciond /run/shm/sciond/sd1-1.sock -dispatcher /run/shm/dispatcher/default.sock -isdas 100-2 -encapip 169.254.1.2 -encapport 10080 -ctrlip 169.254.1.2 -ctrlport 10081
```

Argument `-cli` can be used to enable the optional interactive console.


### Management

#### Interactive console

List of supported commands:
```
Commands:
  clear                 clear the screen
  exit                  exit the program
  help                  display help
  show.route            show.route
  static.route.add      static.route.add <ipv4-subnet> <isdas>
  static.route.del      static.route.del <ipv4-subnet> <isdas>
  static.sig.add        static.sig.add <isdas> <encap-ip> <encap-port> <ctrl-ip> <ctrl-port>
  static.sig.del        static.sig.del <isdas> <encap-ip> <encap-port> <ctrl-ip> <ctrl-port>
```

#### Config files
Config files can be loaded at startup with `-config`. They contain SIG Console commands, one per line.

Config file example:

```
# ETH-Test config file with two SIGs on remote AS 1-10

static.sig.add 1-10 198.51.100.1 10080 198.51.100.1 10080
static.sig.add 1-10 198.51.100.2 10080 198.51.100.2 10080
static.route.add 203.0.113.0/24 1-10
```

### Features and roadmap

Current status:
* Control plane:
  * Static only (using interactive console or config files)
  * Can register multiple SIGs for each remote AS
  * Can register multiple prefixes for each remote AS
  * SIG-SIG transport protocol
* Data plane:
  * Encapsulation/decapsulation is done in user space
  * No load balancing logic
  * IPv4 only

TODOs:
* Control plane:
  * SIG-SIG Keepalive protocol
* Data plane:
  * IPv6 support


### Design
SIGs listen to incoming traffic from other SIGs on UDP port 10080.

When a new SIG for a remote AS is registered, a TUN interface named `scion.<ISD-AS>` is created on the host Linux machine. When a new prefix is added for that AS, a route is injected in the main Linux routing table which redirects traffic to the corresponding tunnel interface. The SIG reads all data on the interface and encapsulates each packet, reinserting it in the main routing process through a scion.local TUN interface.

No lookups are needed in the data plane, because the routing has already been performed by the Linux routing table.


