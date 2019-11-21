#!/usr/bin/env python

##################################################
## This script uses sysrepo swig module in order to take the configuration for one ISD-AS.
## It suscribes for changes on the topology data-store and writes a topology.json file 
## into every service directory (i.e. Border routers, beacon servers, ...).
##################################################
##################################################
## Author: Jordi Subira
## Email: jonieto@student.ethz.ch
##################################################

from __future__ import print_function
import sys
import json
import os, subprocess
import time


import sysrepo as sr #type: ignore
import sysrepo_type as sr_types
import re
import string
from typing import Dict,Any,Iterable, Union
import argparse

r_number = re.compile('[0-9]+')
r_br = re.compile('br\S*')


DIR_APP = os.getcwd()
DIR_HOME = os.getenv("HOME")
DIR_ISD_AS_FORMAT = "gen/ISD{}/AS{}/"
DIR_SCION = os.path.join(DIR_HOME,"go/src/github.com/scionproto/scion/")
SCION_RUN_CMD = "./scion.sh run"
SCION_STOP_CMD = "./scion.sh stop"
SCION_CHECK_CMD = " bin/scmp echo -local '1-ff00:0:110,[127.0.0.1]' -remote '1-ff00:0:112,[127.0.0.1]' -sciondFromIA -c 3"
LIST_SERVICES = ["BeaconService","BorderRouters","BeaconService","PathService","CertificateService"]

TEST_TOPO = False

## Following function are helpers to treat strings for parsing.

def convertion_helper(s: str) -> str:
    #E.g converting isd-as -> to Isd_as ;
    if s == "isd-as" or s == "mtu":
        return s.replace('-','_').upper()
    # from border-routers to BorderRouters
    s = string.capwords(s,'-')
    return s.replace('-','')

#asume one key at the moment
def get_key_list_path(x_path:str) -> str:
    return x_path.split("'")[-2]

def erase_prefix(s:str) -> str:
    return s.split(":")[1]

def get_last_node_name(x_path:str) -> str:
    last_node: str = x_path.split(":")[-1].split("/")[-1]
    last_node = convertion_helper(last_node)
    return last_node

## End helper for strings

# TODO: defining IPv6 treatment too
# Helper function to create the inner-part of the addr-port structure
def create_addr_dict(session, xpath: str, port_name="L4Port") -> Dict[str,Union[Dict[str,Any],str,int,bool]]:
    my_aux_dict = dict()
    my_ipv4: str
    my_port: str

    values = session.get_items(xpath)

    for i in range(values.val_cnt()):
        valType: str = values.val(i).type()
        valXPath: str = values.val(i).xpath()
        if valType == sr_types.SR_CONTAINER_T:
            '''name = get_last_node_name(valXPath)
            json_obj[name]= create_dict(session,valXPath+ "/*")'''
            continue # not container expected
        elif valType == sr_types.SR_LIST_T:
            continue # not list expected
        elif valType == sr_types.SR_UINT16_T or valType == sr_types.SR_UINT32_T: #must be port
            my_port =  int(values.val(i).val_to_string())
        else: # must be string for name or address
            name = get_last_node_name(valXPath)
            if name == "Name":
                continue
            else:
                my_ipv4 = values.val(i).val_to_string()
    
    my_aux_dict ={"Addr" : my_ipv4, port_name : my_port} 
                            
    return my_aux_dict

# TODO: Consider IPv6
# Helper to create JSON addr-port usual structure
def wrapper_addr_port_dict(session, xpath: str, port_name="L4Port", add_type="Public") -> Dict[str,Union[Dict[str,Any],str,int,bool]]:
    return_dict = dict()
    aux_dict = create_addr_dict(session,xpath,port_name)
    return_dict["IPv4"] = {add_type :  aux_dict }
    return return_dict

# Helper function to parse from YANG node names to JSON node names for border router.
def aux_create_br_dict(session, x_path: str, json_obj) -> Dict[str,Union[Dict[str,Any],str,int,bool]]:
    values_add = session.get_items(x_path)

    for j  in range(values_add.val_cnt()):
        valType_add: str = values_add.val(j).type()
        valXPath_add: str = values_add.val(j).xpath()
        if valType_add != sr_types.SR_LIST_T:
            raise Exception("Only expected list values for" + valXPath)
        key:str = erase_prefix(get_key_list_path(valXPath_add))
        if key == "control-address-type":
            json_obj["CtrlAddr"] =  wrapper_addr_port_dict(session, valXPath_add+ "/*")
        elif key == "internal-address-type":
            json_obj["InternalAddrs"] = wrapper_addr_port_dict(session, valXPath_add+ "/*", "OverlayPort","PublicOverlay")
        elif key == "remote-underlay-type":
            json_obj["RemoteOverlay"] =  create_addr_dict(session, valXPath_add+ "/*","OverlayPort")
        elif key == "public-underlay-type":
            json_obj["PublicOverlay"] =  create_addr_dict(session, valXPath_add+ "/*","OverlayPort")
        else:
            raise Exception("Not expected value type" + key)

# Recursive function to create a dict out of the data store configuration.
def create_dict(session, x_path:str) -> Dict[str,Union[Dict[str,Any],str,int,bool]]:
    json_obj: Dict[str,Union[Dict[str,Any],str,int,bool]] = dict()

    values = session.get_items(x_path)

    name:str
    for i  in range(values.val_cnt()):
        valType: str = values.val(i).type()
        valXPath: str = values.val(i).xpath()
        #print(valXPath)
        if valType == sr_types.SR_CONTAINER_T:
            name = get_last_node_name(valXPath)
            if name == "Addresses":
                aux_create_br_dict(session, valXPath + "/*",json_obj)
            elif name == "Underlays":
                aux_create_br_dict(session, valXPath + "/*",json_obj)
            else:
                json_obj[name]= create_dict(session,valXPath+ "/*")
        elif valType == sr_types.SR_LIST_T:
            key:str = get_key_list_path(valXPath)
            #ZooKeeper list, implement special treatment
            if r_number.match(key):
                json_obj[key] = create_dict(session, valXPath+ "/*")

            #BR list, implement special treatment
            elif r_br.match(key):
                json_obj[key] = create_dict(session, valXPath+ "/*")

            else:
                aux_dict = dict()
                aux_dict["Addrs"] =  wrapper_addr_port_dict(session, valXPath+ "/*")
                json_obj[key] = aux_dict
            
        elif valType == sr_types.SR_UINT16_T or valType == sr_types.SR_UINT32_T:
            name = get_last_node_name(valXPath)
            if name=="Number":
                continue
            json_obj[name] = int(values.val(i).val_to_string())
        elif valType == sr_types.SR_BOOL_T:
            name = get_last_node_name(valXPath)
            if values.val(i).val_to_string() == "true":
                json_obj[name] = True
            else:
                json_obj[name] = False
        else: # assume leaf, treat for error TODO: treat numbers
            name = get_last_node_name(valXPath)
            if name == "Name":
                continue
            elif name == "UnderlayProto":
                ul_proto = erase_prefix(values.val(i).val_to_string() )
                if ul_proto == "underlay-udp-ipv4":
                    json_obj["Overlay"] = "UDP/IPv4"
                elif ul_proto == "underlay-tcp-ipv4":
                    json_obj["Overlay"] = "TCP/IPv4"
                else:
                    raise Exception("Not expected overlay protocol: " + values.val(i).val_to_string())
            elif name == "Link":
                json_obj["LinkTo"] = values.val(i).val_to_string().upper()
            elif name == "Address":
                json_obj["Addr"] = values.val(i).val_to_string()
            else:
                json_obj[name] = values.val(i).val_to_string()

    return json_obj

# This function writes the topology.json file within every directory service
def write_isd_as(json_topo) -> None:
	dirs_to_write = list()
	dirs_to_write.append("endhost")
	if not "ISD_AS" in json_topo:
		raise Exception("Expected ISD-AS in the topology")
	number_isd = json_topo["ISD_AS"].split("-")[0]
	as_name = json_topo["ISD_AS"].split("-")[1].replace(":","_")
	for service in LIST_SERVICES:
		for key in json_topo[service].keys():
			dirs_to_write.append(key)

	dir_isd_as = DIR_ISD_AS_FORMAT.format(number_isd,as_name)
	#print(os.path.join(DIR_HOME,DIR_SCION,dir_isd_as))
	for service_dir in dirs_to_write:
		#print("I would write in :", os.path.join(service_dir,'topology_new.json') )
		os.chdir(os.path.join(DIR_HOME,DIR_SCION,dir_isd_as))
		f = open(os.path.join(service_dir,'topology.json'),'w+')
		f.truncate(0)
		json_st:str = json.dumps(json_topo, indent=4)
		f.write(json_st)
		f.close()
		print ("------ TOPOLOGY created in "+ os.path.join(dir_isd_as,service_dir) +" ------")

def testTopo() -> None:

	os.chdir(DIR_SCION)
    
	time.sleep(3)
	print ("------ RUNNING NEW CONFIGURATION ------")
	os.system(SCION_RUN_CMD)

	time.sleep(3)

	print ("------ CHECKING NEW CONFIGURATION ------")
	os.system(SCION_CHECK_CMD)

	time.sleep(3)
	print ("------ RUNNING NEW CONFIGURATION ------")
	os.system(SCION_STOP_CMD)


	print ("------ DONE ------")
	os.chdir(DIR_APP)



# Function to write topology file in DIR_BR, apply config (run), test and stop.
def change_current_config(session, module_name: str):
    try:
        select_xpath: str = "/" + module_name + ":topology/*"

        json_obj: Dict[str,Any]= create_dict(session,select_xpath)

        write_isd_as(json_obj)

        if TEST_TOPO:
        	testTopo()

        #print_current_config(session,module_name)

    except Exception as e:
        print(e)

#Printing configuration in XPATH format
def print_current_config(session, module_name):
    select_xpath: str = "/" + module_name + ":*//*"

    values = session.get_items(select_xpath)

    for i in range(values.val_cnt()):
        print (values.val(i).to_string(),end='')

# Callback for subscribed client of given session whenever configuration changes.
def module_change_cb(sess, module_name, event, private_ctx):
    print ("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n")

    change_current_config(sess, module_name)

    return sr.SR_ERR_OK

# NOTE:`Conenction`, `Session` and `Subscribe` could throw an exception.
if __name__ == '__main__':
    try:
        module_name: str = "scion-topology"

        parser = argparse.ArgumentParser(prog='wr_test_topo')
        parser.add_argument('--test', help="test topology", action="store_true")
        args = parser.parse_args()

        TEST_TOPO = args.test

        # connect to sysrepo
        conn = sr.Connection(module_name)

        # start session
        sess = sr.Session(conn)

        # subscribe for changes in running config */
        subscribe = sr.Subscribe(sess)

        subscribe.module_change_subscribe(module_name, module_change_cb, None, 0, sr.SR_SUBSCR_DEFAULT | sr.SR_SUBSCR_APPLY_ONLY)

        print ("\n\n ========== READING STARTUP CONFIG: ==========\n")
        try:
            print_current_config(sess, module_name)
        except Exception as e:
            print (e)

        print ("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n")

        change_current_config(sess,module_name)

        sr.global_loop()

        print ("Application exit requested, exiting.\n")

    except Exception as e:
        print (e)

