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

Run the SIG as root (note that root needs to have a valid path to the SIG binary):

```
sudo -E sig -config sig.config -sciond /run/shm/sciond/sd1-1.sock
```


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
  static.sig.add        static.sig.add <isdas> <ipv4-address> <port>
  static.sig.del        static.sig.del <isdas> <ipv4-address> <port>
```

#### Config files
Config files can be loaded at startup with `-config`. They contain SIG Console commands, one per line.

Config file example:

```
# ETH-Test config file with two SIGs on remote AS 1-10

static.sig.add 1-10 198.51.100.1 10080
static.sig.add 1-10 198.51.100.2 10080
static.route.add 203.0.113.0/24 1-10
```

### Features and roadmap

Current status:
* Control plane:
  * Static only (using built-in console and config files)
  * Built-in interactive console
  * Can register multiple SIGs for each remote AS
  * Can register multiple prefixes for each remote AS
* Data plane:
  * Current performance: 3.3Mbps on Vagrant testbed using iperf TCP (out of 1.03Gbps native performance)
  * Encapsulation/decapsulation is done in user space
  * Per packet processing, no async operations
  * Only POC IP in IP encapsulation
  * No SIG-SIG packet aggregation protocol
  * No load balancing logic
  * Only tested for IPv4

TODOs:
* Control plane:
  * Run as a service and connect to it using remote console
* Data plane:
  * Implement SCION/UDP encapsulation
  * Implement SIG-SIG packet aggregation protocol
  * Implement Round Robin load balancer
  * Move encapsulation and decapsulation to kernel space
  * Add IPv6 support


### Design
SIGs listen to incoming traffic from other SIGs on UDP port 10080.

When a new SIG for a remote AS is registered, a TUN interface named `scion.<ISD-AS>` is created on the host Linux machine. When a new prefix is added for that AS, a route is injected in the main Linux routing table which redirects traffic to the corresponding tunnel interface. The SIG reads all data on the interface and encapsulates each packet, reinserting it in the main routing process through a scion.local TUN interface.

No lookups are needed in the data plane, because the routing has already been performed by the Linux routing table.


