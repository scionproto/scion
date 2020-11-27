package config

const idSample = "bootstrapper"

const bootstrapperSample = `
# The network interface to use (default "")
interface = "NIC"
# The folder where the SD files will be created (default "/etc/scion")
scion_folder = "/etc/scion"
# The SD configuration files to override the default one (default "")
sd_conf = ""

# Discovery mechanisms
[mock]
	# Whether to enable the fake discovery or not (default false)
	# This discovery mechanisms is used for testing purposes
	enable = false
	# The address to return when simulating a network discovery (default "")
	address = ""
[dhcp]
	# Whether to enable DHCP discovery or not (default false)
	enable = false
[dnssd]
	# Whether to enable DNS SRV discovery or not (default false)
	enable_srv = true
	# Whether to enable DNS-SD discovery or not (default false)
	enable_sd = true
	# Whether to enable DNS-NAPTR discovery or not (default false)
	enable_naptr = true
[mdns]
	# Whether to enable mDNS discovery or not (default false)
  	enable = true
`
