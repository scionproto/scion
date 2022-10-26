// Copyright 2016 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package topology wraps two versions of the topology. The first is RWTopology, which permits
other packages to change topology information. The second topology type is Topology. It is
used by packages that only need read access to the topology.

The full JSON format for a SCION address looks like the following:

	"Addrs":{
	  "IPv4": {
	    "Public": {
	      "Addr": "192.168.1.1",
	      "L4Port": 31000,
	      "OverlayPort": 30041,
	    },
	    "Bind": {
	      "Addr": "127.0.0.1",
	      "L4Port": 31000,
	      "OverlayPort": 30041,
	    }
	  },
	  "IPv6": {
	    "Public": {
	      "Addr": "2001:db8:f00:b43::1",
	      "L4Port": 31000,
	      "OverlayPort": 30041,
	    },
	    "Bind": {
	      "Addr": "2001:db8:f00:b43::1",
	      "L4Port": 31000,
	      "OverlayPort": 30041,
	    }
	  }
	}

Go applications parse the above in the following manner:
  - Properties not listed in the above are ignored;
  - If a "Bind" property is found, parsing will return an error; bind addresses for SCION sockets
    are currently not supported.
  - If an "OverlayPort" property is found, parsing will return an error; custom underlay ports for
    SCION sockets are currently not supported. NOTE: the JSON file uses the old "Overlay" term for
    the AS-level UDP fabric that forwards traffic. The new term for this (which is also used in the
    Go code base) is "Underlay".
  - If both property "IPv4" and "IPv6" are present, the address is assumed to be IPv6 and only
    that address is used (in other words, the IPv4 property contents are discarded); dual stacked
    addresses are currently not supported.

The full JSON format for a BR data-plane AS-external underlay socket looks like the following:

	{
	  "Overlay": "UDP/IPv4",
	  "ISD_AS": "1-ff00:0:1",
	  "Bandwidth": 1000,
	  "PublicOverlay": {
	    "Addr": "192.168.0.1",
	    "OverlayPort": 50000,
	  },
	  "BindOverlay": {
	    "Addr": "127.0.0.1",
	  },
	  "RemoteOverlay": {
	    "Addr": "192.168.0.2",
	    "OverlayPort": 50000,
	  },
	  "LinkTo": "CORE",
	  "MTU": 1472,
	}

To construct a BR data-plane AS-external underlay socket address out of the above, the following
rules are used:
  - Properties "ISD_AS", "Bandwidth", "LinkTo", and "MTU" are ignored. All unknown properties not
    included in the above example are silently ignored.
  - Properties "PublicOverlay" and "RemoteOverlay" must exist. An error is returned if one of them
    is missing.
  - Property "BindOverlay" is optional. If it is not present, then the address checks below do not
    apply to property "Addr" under "BindOverlay". If it is present, the address is subject to all
    format constraints below.
  - If property "Overlay" is "UDP/IPv4", all "Addr" properties are checked to be IPv4. If one cannot
    be parsed as an IPv4 address, an error is returned. If the address is the empty string, an error
    is returned.
  - If property "Overlay" is "UDP/IPv6", all "Addr" properties are checked to be IPv6. If one cannot
    be parsed as an IPv6 address, an error is returned. If the address is the empty string, an error
    is returned.
  - If a port property is missing, it is assumed to be 0. The application is free to interpret this
    however it sees fit.

The full JSON format for a BR data-plane AS-internal underlay socket address looks like the
following:

	{
	  "IPv4": {
	    "PublicOverlay": {
	      "Addr": "192.168.0.1",
	      "OverlayPort": 31000,
	    },
	    BindOverlay": {
	      "Addr": "127.0.0.1"
	    }
	  },
	  "IPv6": {
	    "PublicOverlay": {
	      "Addr": "2001:db8:f00:b43::1",
	      "OverlayPort": 31000
	    },
	    "BindOverlay": {
	      "Addr": "::1"
	    }
	  }
	}

To construct a BR data-plane AS-internal underlay socket address out of the above, the following
rules are used:
  - Properties not listed in the above are ignored.
  - If both property "IPv4" and "IPv6" are present, the address is assumed to be IPv6 and only that
    address is used (in other words, the IPv4 property contents are discarded); dual stacked
    addresses are currently not supported.
  - For the chosen address, the underlay address is taken from the "BindOverlay" property; if this
    is the case, the "PublicOverlay" address is never parsed. The address must match the address
    type in the top-level property (IPv4 or IPv6), otherwise an error is returned. If the
    "BindOverlay" property does not exist, the underlay address is taken from the "PublicOverlay"
    property. The address must match the address type in the top-level property, otherwise an error
    is returned. No matter which address is used, the port is always taken from the "PublicOverlay"
    property". An unset port is interpreted as 0.
*/
package topology

//vim: tw=78 fo+=t
