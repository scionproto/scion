# YANG modules and NETCONF

The python script uses sysrepo+Netopeer2 as persistance and NETCONF
Server solutions. For more information about how to install sysrepo+Netopeer2
see: <https://github.com/sysrepo/sysrepo>
and <https://github.com/CESNET/Netopeer2/tree/master/server>.

## Installation YANG modules

YANG module can be installed using CLI as follows:

```sh
sysrepoctl --install --yang={MODULE_NAME} --owner={USER}:{GROUP} --permission={OCTAL-REP}
```

More information can be found here: <http://www.sysrepo.org/>.

## Usage python scripts

The `write_topo.py` script can be used as follows:

```sh
python write_topo.py [--test]
```

Note that if flag *test* is used `topology.json` will be send to the standard
output upon changes (received by the NETCONF server). Otherwise,
`topology.json` will be overwritten on `$HOME/go/src/github.com/scionproto/scion/gen/ISD{}/AS{}/{SERVICE}`
for every `{SERVICE}` on the configured `ISD-AS`.