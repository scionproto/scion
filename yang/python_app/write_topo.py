#!/usr/bin/env python
"""
:mod:`write_topo` -- YANG topology.json generator
=================================================

This module suscribes for changes to the scion-topology data store and
changes the topology.json files
"""
##################################################
# Copyright 2019 ETH Zurich
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##################################################
##################################################
# This script uses sysrepo swig module in order to take the configuration for
# one ISD-AS.
# It suscribes for changes on the topology data-store and writes the
# topology.json file
# into every service directory (i.e. Border routers, beacon servers, ...).
##################################################
##################################################
# Author: Jordi Subira
# Email: jonieto@student.ethz.ch
##################################################

import json
import os
import argparse
import re
import traceback
from typing import Dict, List, Any, Union, Optional  # noqa


import sysrepo as sr  # type: ignore
import sysrepo_type as sr_types

import str_helper as helper

R_NUMBER = re.compile(r'[0-9]+')
R_BR = re.compile(r'br\S*')
R_IPv4 = re.compile('(' +
                    r'([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.)' +
                    '{3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])')

R_IPv6 = re.compile(r'((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}' +
                    '((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|' +
                    r'(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}' +
                    '(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))')

DIR_APP = os.getcwd()  # type: str

DIR_HOME = os.getenv("HOME")  # type: Optional[str]
if DIR_HOME is None:
    raise Exception("No defined HOME env.")

DIR_ISD_AS_FORMAT = "gen/ISD{}/AS{}/"
DIR_SCION = os.path.join(DIR_HOME,
                         "go/src/github.com/scionproto/scion/")  # type: str

LIST_SERVICES = ["BorderRouters", "ControlService"]
TUPLE_UNDERLAY_CONT = ("RemoteUnderlay", "PublicUnderlay", "BindUnderlay")
TUPLE_BR_ADDRESS_CONT = ("ControlAddress", "InternalAddress")

_PARSING = dict()

AddrPortType = Dict[str, Union[int, str]]
TopologyDictType = Dict[str, Union[Dict[str, Any], str, int, bool]]


def _create_addr_dict(session, xpath: str,
                      port_name: str = "L4Port") -> AddrPortType:
    """Helper function to create the inner-part of the addr-port structure."""

    my_aux_dict = dict()  # type: AddrPortType

    values = session.get_items(xpath)

    # In case empty BindUnderlay
    if values is None:
        return my_aux_dict

    for i in range(values.val_cnt()):
        val_type = values.val(i).type()  # type: str
        val_xpath = values.val(i).xpath()  # type: str
        if val_type in (sr_types.SR_UINT16_T, sr_types.SR_UINT32_T):
            my_port = int(values.val(i).val_to_string())
        elif val_type == sr_types.SR_STRING_T:
            # must be string for name or address
            name = helper.get_last_node_name(val_xpath)  # type: str
            if name != "Name":
                my_ip = values.val(i).val_to_string()  # type: str
        else:
            raise TypeError("Not type list/container on address structure" +
                            " for " + val_xpath + ", type: " + val_type)

    my_aux_dict = {"Addr": my_ip, port_name: my_port}

    return my_aux_dict


def _wrapper_addr_port_dict(session, xpath: str,
                            port_name: str = "L4Port",
                            add_type: str = "Public"
                            ) -> Dict[str, Dict[str, AddrPortType]]:
    """Helper to create JSON addr-port usual structure."""

    return_dict = dict()
    aux_dict = _create_addr_dict(session, xpath,
                                 port_name)  # type: Dict[str, Union[int, str]]
    if R_IPv4.match(str(aux_dict["Addr"])):
        return_dict["IPv4"] = {add_type:  aux_dict}
    elif R_IPv6.match(str(aux_dict["Addr"])):
        return_dict["IPv6"] = {add_type:  aux_dict}
    else:
        raise TypeError("Address does not fulfill neither IPv4 or IPv6 format")

    return return_dict


def _aux_create_br_dict(session, x_path: str,
                        json_obj: TopologyDictType) -> None:
    """Helper function to parse from YANG node names to JSON node names
    for border router.
    """

    values_add = session.get_items(x_path)

    for j in range(values_add.val_cnt()):
        val_type_add = values_add.val(j).type()  # type: str
        val_xpath_add = values_add.val(j).xpath()  # type: str
        if val_type_add != sr_types.SR_CONTAINER_T:
            raise TypeError("Only expected container values for" +
                            val_xpath_add)

        name = helper.get_last_node_name(val_xpath_add)  # type: str
        val_xpath_add += "/*"
        if name == "ControlAddress":
            json_obj["CtrlAddr"] = _wrapper_addr_port_dict(session,
                                                           val_xpath_add
                                                           )
        elif name == "InternalAddress":
            json_obj["InternalAddrs"] = _wrapper_addr_port_dict(session,
                                                                val_xpath_add,
                                                                "OverlayPort",
                                                                "PublicOverlay"
                                                                )
        elif name == "RemoteUnderlay":
            json_obj["RemoteOverlay"] = _create_addr_dict(session,
                                                          val_xpath_add,
                                                          "OverlayPort")
        elif name == "PublicUnderlay":
            json_obj["PublicOverlay"] = _create_addr_dict(session,
                                                          val_xpath_add,
                                                          "OverlayPort")
        elif name == "BindUnderlay":
            aux_dict = _create_addr_dict(session,
                                         val_xpath_add,
                                         "OverlayPort")  # tpye: AddrPortType

            # Checking not to write empty bind-underlay
            if aux_dict:
                json_obj["BindOverlay"] = aux_dict
        else:
            raise TypeError("Not expected value type" + name)


def _aux_attr_list(session, xpath: str) -> List[str]:
    ret_list = list()

    values = session.get_items(xpath)

    # In case empty BindUnderlay
    if values is None:
        return ret_list

    for i in range(values.val_cnt()):
        val_type = values.val(i).type()  # type: str
        val_xpath = values.val(i).xpath()  # type: str
        if val_type != sr_types.SR_IDENTITYREF_T:
            raise TypeError("Not type identityref on Attributes list" +
                            " for " + val_xpath + ", type: " + val_type)
        id_ref_value = values.val(i).val_to_string()  # type: str
        ret_list.append(helper.get_value_identityref(id_ref_value))

    return ret_list


def _create_dict(session, x_path: str) -> TopologyDictType:
    """Recursive function to create a dict out of the data
    store configuration.
    """

    json_obj = dict()  # type: TopologyDictType

    values = session.get_items(x_path)
    if values is None:
        return json_obj

    for i in range(values.val_cnt()):
        val_type = values.val(i).type()  # type: str
        val_xpath = values.val(i).xpath()  # type: str
        if val_type == sr_types.SR_CONTAINER_T:
            name = helper.get_last_node_name(val_xpath)  # type: str
            if name in TUPLE_UNDERLAY_CONT or name in TUPLE_BR_ADDRESS_CONT:
                _aux_create_br_dict(session, val_xpath, json_obj)
            elif name == "Attributes":
                val_xpath += "/*"
                aux_list = _aux_attr_list(session,
                                          val_xpath)  # type: List[str]
                json_obj[name] = aux_list
            else:
                aux_dict = _create_dict(session,
                                        val_xpath +
                                        "/*")  # type: TopologyDictType
                # Checking not to write empty
                if aux_dict:
                    json_obj[name] = aux_dict

        elif val_type == sr_types.SR_LIST_T:
            key = helper.get_key_list_path(val_xpath)  # type: str
            # Interfaces, implement special treatment
            if R_NUMBER.match(key):
                json_obj[key] = _create_dict(session, val_xpath + "/*")

            # BR list, implement special treatment
            elif R_BR.match(key):
                json_obj[key] = _create_dict(session, val_xpath + "/*")

            # Else consider other services
            else:
                aux_dict = dict()
                aux_dict["Addrs"] = _wrapper_addr_port_dict(session,
                                                            val_xpath + "/*")
                json_obj[key] = aux_dict

        elif val_type in (sr_types.SR_UINT16_T, sr_types.SR_UINT32_T):
            name = helper.get_last_node_name(val_xpath)
            if name != "Number":
                json_obj[name] = int(values.val(i).val_to_string())
        elif val_type == sr_types.SR_BOOL_T:
            name = helper.get_last_node_name(val_xpath)
            if values.val(i).val_to_string() == "true":
                json_obj[name] = True
            else:
                json_obj[name] = False
        elif val_type in (sr_types.SR_STRING_T, sr_types.SR_IDENTITYREF_T,
                          sr_types.SR_ENUM_T):
            name = helper.get_last_node_name(val_xpath)
            if name == "Name":
                continue
            if name == "UnderlayProto":
                ul_proto = helper.erase_prefix(values.val(i).val_to_string())
                if ul_proto == "underlay-udp-ipv4":
                    json_obj["Overlay"] = "UDP/IPv4"
                elif ul_proto == "underlay-tcp-ipv4":
                    json_obj["Overlay"] = "TCP/IPv4"
                elif ul_proto == "underlay-udp-ipv6":
                    json_obj["Overlay"] = "UDP/IPv6"
                elif ul_proto == "underlay-tcp-ipv6":
                    json_obj["Overlay"] = "TCP/IPv6"
                else:
                    raise ValueError("Not expected underlay protocol: " +
                                     values.val(i).val_to_string())
            elif name == "Link":
                json_obj["LinkTo"] = values.val(i).val_to_string().upper()
            elif name == "Address":
                json_obj["Addr"] = values.val(i).val_to_string()
            else:
                json_obj[name] = values.val(i).val_to_string()
        else:
            raise TypeError("Not expected YANG type for " + val_xpath +
                            "is type " + str(val_type))

    return json_obj


def _write_isd_as(json_topo: Dict[str, Any]) -> None:
    """ This function writes the json file within every service directory."""

    dirs_to_write = list()
    dirs_to_write.append("endhost")

    if "ISD_AS" not in json_topo:
        raise ValueError("Expected ISD-AS in the topology configuration.")
    number_isd = json_topo["ISD_AS"].split("-")[0]
    as_name = json_topo["ISD_AS"].split("-")[1].replace(":", "_")
    for service in LIST_SERVICES:
        if service in json_topo.keys():
            for key in json_topo[service].keys():
                dirs_to_write.append(key)

    dir_isd_as = DIR_ISD_AS_FORMAT.format(number_isd, as_name)
    dir_isd_as = os.path.join(DIR_SCION, dir_isd_as)
    if not os.path.exists(dir_isd_as):
        raise FileNotFoundError(dir_isd_as + "doesn't exist.")
    for service_dir in dirs_to_write:
        os.chdir(dir_isd_as)
        topo_file = open(os.path.join(service_dir, 'topology.json'), 'w+')
        topo_file.truncate(0)
        json_st = json.dumps(json_topo, indent=4)  # type:str
        topo_file.write(json_st)
        topo_file.close()
        print("------ TOPOLOGY created in " +
              os.path.join(dir_isd_as, service_dir) + " ------")


def _change_current_config(session, module_name: str) -> None:
    """Function to write topology file or upon NETCONF changes."""

    select_xpath = "/" + module_name + ":topology/*"

    try:
        json_obj = _create_dict(session,
                                select_xpath)  # type: TopologyDictType
    except Exception:
        traceback.print_exc()
        raise

    if not json_obj:
        print("No changes applied.")
        return

    if 'test' in _PARSING and not _PARSING['test']:
        try:
            _write_isd_as(json_obj)
        except Exception:
            traceback.print_exc()
            raise
    else:
        print(json.dumps(json_obj, indent=4))
    print("END Write.")


def _print_current_config(session, module_name) -> None:
    """Print XPath configuration for the module."""

    select_xpath = "/" + module_name + ":*//*"

    values = session.get_items(select_xpath)
    if values is None:
        print("Empty Data Store")
        return

    for i in range(values.val_cnt()):
        print(values.val(i).to_string(), end='')


def module_change_cb(sess, module_name, event, private_ctx):
    """Callback for subscribed client of given session whenever configuration
    changes.
    """

    print("\n\n ========== CONFIG HAS CHANGED, "
          "CURRENT RUNNING CONFIG: ==========\n")

    _change_current_config(sess, module_name)

    return sr.SR_ERR_OK


def main():
    """Main function."""

    module_name = "scion-topology"

    parser = argparse.ArgumentParser(prog='write_topo.py')
    parser.add_argument('--test', help="print stdout json file",
                        action="store_true")

    for k, v in vars(parser.parse_args()).items():
        _PARSING[k] = v

    # connect to sysrepo
    conn = sr.Connection(module_name)
    # start session
    sess = sr.Session(conn)
    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)
    # setting callback
    subscribe.module_change_subscribe(module_name,
                                      module_change_cb, None, 0,
                                      sr.SR_SUBSCR_DEFAULT |
                                      sr.SR_SUBSCR_APPLY_ONLY)

    print("\n\n ========== READING STARTUP CONFIG: ==========\n")
    _print_current_config(sess, module_name)

    _change_current_config(sess, module_name)
    print("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n")

    sr.global_loop()

    print("Application exit requested, exiting.\n")


if __name__ == '__main__':
    main()
