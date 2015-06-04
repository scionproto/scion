#!/usr/bin/python
#
# brite2ns -- an ad-hoc topology convertion tool (BRITE -> NS compatible)
#   by Andre Detsch <detsch@exatas.unisinos.br>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

import string
import sys

print "brite2ns -- an ad-hoc topology convertion tool (BRITE -> NS compatible)"
print " by Andre Detsch <detsch@exatas.unisinos.br>"
print
if len(sys.argv) < 3:
	print "Usage: bryte2ns <in_brite_file> <out_ns_file>"
	print
	sys.exit(0)

print "Converting "+sys.argv[1] +" --> "+sys.argv[2]+".     Reading input (BRITE) file... ",
sys.stdout.flush()

f = open(sys.argv[1])

state = 0 #0-> skipping; 1->reading nodes; 2->reading edges;

#keep the bandwidth from the BRITE file (or use the "linkBW" parameter from the tcl script) 
keepBriteBandwith = 0

nodes = []
edges = []

for line in f.readlines() :
	list = string.split(line)
	if len(list)==0 or list[0][0] == '#':
		continue

	if state == 0 :
		if list[0] == "Nodes:" :
			state = 1

	elif state == 1 :
		if list[0] == "Edges:" :
			state = 2
		else :
			#just keep node index
			nodes.append(list[0])

	elif state == 2 :
		#just keep from, to, delay and bw
		edges.append([list[1], list[2], list[3], list[4]])

f.close()

print " done!    Creating output (NS) file... ",
sys.stdout.flush()

#brite file parsing done. It's time to create the ns file

o = open(sys.argv[2], "w+")

o.write('\n\n#Usage:\n')
o.write('# - Source the current file on your NS-tcl script -> source <this_file.tcl>\n')
o.write('# - Creta a NS Simulator instance                 -> set ns [new Simulator -multicast on]\n')
o.write('# - Call the "create_topology" procedure          -> set returned_number_of_nodes [create-topology ns nodes 1Mbps]\n')
o.write('#   where "ns"    is the simulator instance;\n')
o.write('#         "nodes" will contain (after procedure retun) the array of created nodes, \n')
o.write('#                 so that you can do things like attach agents on it (e.g. $ns attach-agent $n(0) $someAgent);\n')
o.write('#         "1Mbps" is a example of the bandwith parameter, which sets the bandwiths for all links\n\n\n')  

o.write("proc create-topology {nsns node linkBW} {\n")
o.write("\tupvar $node n\n")
o.write("\tupvar $nsns ns\n")
o.write("\tfor {set i 0} {$i < "+ str(len(nodes)) +"} {incr i} {\n")
o.write("\t\tset n($i) [$ns node]\n")
o.write("\t}\n")

if keepBriteBandwith :
    for edge in edges :
	o.write("\t$ns duplex-link $n("+str(nodes.index(edge[0])) +") $n("+str(nodes.index(edge[1]))+") "+edge[3]+"Mbps "+edge[2] +"ms DropTail\n")
else :
    for edge in edges :
	o.write("\t$ns duplex-link $n("+str(nodes.index(edge[0])) +") $n("+str(nodes.index(edge[1]))+") $linkBW "+edge[2] +"ms DropTail\n")


o.write("\n\treturn "+str(len(nodes))+"\n}\n")
o.close()
print "done!"
