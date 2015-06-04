# Import the files made by 
# BRITE:  Boston university Representative Internet Topology gEnerator
#
# Version 0.7
#
# Stan Rost 12/1/2001  (stanrost@mit.edu)

# Imports a BRITE toplogy file, 
# creates two variables:
#  an array of Extended Vertices and 
#  an array of Extended Edges.

# An Extended Vertex V contains the following information:
# V(index)
# V(inDegree) = # incoming edges
# V(outDegree) = # outgoing edges
# V(ASid) = # of ASid
# V(AStype) = type of the AS
# V(node) = actual ns node associated with this vertex

# An Extended Edge E contains the following information:
# E(from) = id of the from node
# E(to) = id of the to node
# E(delay)
# E(bw) = bandwidth
# E(fromAS)
# E(toAS)
# E(edgeType) = 
# E(dirxn) = U if undirectional
# E(link) = actual ns link associated with this edge

proc import_brite { briteFile numVertsOut  vertsVarOut numEdgesOut edgesVarOut } {

upvar $numVertsOut numNodes
upvar $numEdgesOut numEdges
upvar $vertsVarOut vertsVar
upvar $edgesVarOut edgesVar

    # Open the file
    set bf [ open $briteFile r ]

    # Read the number of nodes, edges
    set hdrCount [ gets $bf hdrLine ]
#    puts "hdrLine is $hdrLine"


    # Get numNodes, numEdges
    set hdrList [ split $hdrLine "() ,:"]
 #   puts "hdrList is $hdrList"

    set numNodes [ lindex $hdrList 4 ]
 
    set numEdges [ lindex $hdrList 7 ]
 #   puts "numNodes is $numNodes"
 #   puts "numEdges is $numEdges"

    # Skip model, empty line
    gets $bf
    gets $bf

    # Skip nodes
    gets $bf

    # Read in nodes
    for { set i 0 } { $i < $numNodes } { incr i } {

	gets $bf nodeLine

	set nodeLine [ split $nodeLine " \t" ]

#	puts "NodeLine <$nodeLine>"

	set vertsVar($i,index) [ lindex $nodeLine 0 ]

	# Skip xCoord yCoord

	set vertsVar($i,inDegree) [ lindex $nodeLine 3 ]
	set vertsVar($i,outDegree) [ lindex $nodeLine 4 ]

#	puts "Got index = $vertsVar($i,index), inDegree = $vertsVar($i,inDegree), outDegree = $vertsVar($i,outDegree)"

	# (SAR) Uncomment later, if needed
	# set vertsVar($i,ASid) [ lindex $nodeLine 5 ]
	# set vertsVar($i,AStype) [ lindex $nodeLine 6 ]
    }

    # Skip empty lines
    gets $bf
    gets $bf

    # Skip Edges: ( # ) lines
    gets $bf

    # Read in edges
    for { set i 0 } { $i < $numEdges } { incr i } {

	gets $bf edgeLine

	set edgeLine [ split $edgeLine " \t" ]

#	puts "EdgeLine <$edgeLine>"

	set edgesVar($i,index) [ lindex $edgeLine 0 ]
	set edgesVar($i,from) [ lindex $edgeLine 1 ]
	set edgesVar($i,to) [ lindex $edgeLine 2 ]

	# Skip length

	set edgesVar($i,delay) [ lindex $edgeLine 4 ]
	set edgesVar($i,bw) [ lindex $edgeLine 5 ]

	set edgesVar($i,fromAS) [ lindex $edgeLine 6 ]
	set edgesVar($i,toAS) [ lindex $edgeLine 7 ]

	set edgesVar($i,edgeType) [ lindex $edgeLine 8 ]
	set edgesVar($i,dirxn) [ lindex $edgeLine 9 ]

#	puts "Got index = $edgesVar($i,index), from = $edgesVar($i,from), to = $edgesVar($i,to), delay = $edgesVar($i,delay), bw = $edgesVar($i,bw), fromAS = $edgesVar($i,fromAS), toAS = $edgesVar($i,toAS), edgeType = $edgesVar($i,edgeType), dirxn = $edgesVar($i,dirxn)"
	
    }

    close $bf

}

# Verts is the Extended Vertices array as obtained above
# Edges is the Extended Edges array as shown above
proc create_brite_topo { ns numVertsOut vertsOut numEdgesOut edgesOut qtype } {

upvar $numVertsOut numVerts
upvar $numEdgesOut numEdges
upvar $edgesOut edges
upvar $vertsOut verts

    for { set i 0 } { $i < $numVerts } { incr i } {

#	if { [ expr $i % 100 ] == 0 } {
#	    puts "Making node ($i) ..."
#	}

	set verts($i,node) [ $ns node ]
    }

    for { set i 0 } { $i < $numEdges } { incr i } {

#	if { [ expr $i % 100 ] == 0} {
#	    puts "Connecting link ($i) ..."
#	}

	set nodeIndex1 $edges($i,from)
	set nodeIndex2 $edges($i,to)
	
	if { $edges($i,dirxn) == "U" } {
	    set linkType "duplex-link"
	} else {
	    set linkType "simplex-link"
	}

	$ns $linkType $verts($nodeIndex1,node) $verts($nodeIndex2,node) [ append $edges($i,bw) "Mb" ] [ append $edges($i,delay) "ms" ] $qtype
    }
        
    
}

# import_brite "../test.topo.brite" numVerts verts numEdges edges
# puts "-------------------------- (1)"
# set ns [ new Simulator ]
# puts "-------------------------- (2)"
# create_brite_topo $ns numVerts verts numEdges edges DropTail
