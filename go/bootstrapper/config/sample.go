package config

const idSample = "bootstrapper"

const bootstrapperSample = `
# The network interface to use (default "")
Interface = eth0

# The path where sciond config files will be placed (default ".")
SciondDirectory = sciond/

[mechanisms]

DHCP = true

mDNS = true

DNSSD = true

DNSNAPTR = true
`
