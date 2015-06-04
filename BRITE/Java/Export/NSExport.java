package Export;

import Topology.*;
import Graph.*;
import Model.*;
import Util.*;

import java.io.*;
import java.util.*;


/** 


*/


public class NSExport {

    private Topology t;
    private BufferedWriter bw;
    private BufferedReader br;
    
    public NSExport(Topology t, File outFile) {
	this.t = t;
	try {
	    bw = new BufferedWriter(new FileWriter(outFile));
	}
	catch (IOException e) {
	    Util.ERR("Error creating BufferedWriter in NSExport: " +e); 
	}
	
	/*try {
	  br = new BufferedReader(new FileReader("nsOptions.conf"));
	}
	catch (IOException e) {
	Util.ERR("Error creating BufferedReader for file: nsOptions.conf", e);
	}*/
    }
    
    public void export() throws Exception {
      Util.MSG("Producing export file for ns ");
	Graph g = t.getGraph();
	
	Node[] nodes = g.getNodesArray();
	
	HashMap id2id = new HashMap(nodes.length);
	for (int i=0; i<nodes.length; ++i) {
	    id2id.put(new Integer(nodes[i].getID()), new Integer(i));
	}

	Arrays.sort(nodes, Node.IDcomparator);
	Edge[] edges = g.getEdgesArray();
	Arrays.sort(edges, Edge.SrcIDComparator);
	
	bw.write("# Export from BRITE topology"); 
	bw.newLine();
	bw.write("# Generator Model Used: "+ t.getModel().toString());
	bw.newLine(); bw.newLine();
	bw.newLine(); bw.newLine();
	bw.write("proc create_topology{} {"); bw.newLine();
	bw.write("\tglobal ns");  bw.newLine();
	bw.newLine();
	bw.write("\t#nodes:");  bw.newLine();
	bw.write("\tset num_node "+nodes.length); bw.newLine();
	bw.write("\tfor {set i 0} {$i < $num_node} {incr i} {"); bw.newLine();
	bw.write("\t   set n($i) [$ns node]"); bw.newLine();
	bw.write("\t}"); bw.newLine();
	bw.newLine();
	bw.write("\t #links:"); bw.newLine();
	bw.write("\tset qtype DropTail"); bw.newLine(); bw.newLine();
	for (int i=0; i<edges.length; ++i) {
	  Edge e = edges[i];
	  int srcIndex = ((Integer) id2id.get(new Integer(e.getSrc().getID()))).intValue();
	  int dstIndex = ((Integer) id2id.get(new Integer(e.getDst().getID()))).intValue();
	  if (e.getDirection() == GraphConstants.DIRECTED) {
	    /*simplex link*/
	    bw.write("\t$ns simplex-link ");
	  }
	  else {
	    bw.write("\t$ns duplex-link ");
	  }
	  bw.write("$n("+srcIndex+") $n("+dstIndex+") "+ e.getBW()+"Mb "+e.getDelay()+"ms $qtype");
	  bw.newLine();
	}
	bw.newLine(); 
	bw.write("}   #end function create_topology"); 
	bw.newLine();
	
	// helper function to extract leaf nodes, i.e. nodes with degree 1
	bw.newLine();
	bw.write("#-------------  extract_leaf_nodes:  array with smallest degree nodes -----");
	bw.newLine();
	
	Node[] leaves = g.getLeafNodes();
	
	bw.write("proc extract_leaf_nodes{} {"); bw.newLine();
	bw.newLine();
	int minDeg = g.getNumNeighborsOf(leaves[0]);
	bw.write("\t# minimum degree in this graph is: " + minDeg+". ");
	bw.newLine();
	for (int i=0; i<leaves.length; ++i) {
	  bw.write("\tset leaf("+i+")  "+ leaves[i]);
	  bw.newLine();
	}
	
	bw.newLine();
	bw.write("}  #end function extract_leaf_nodes");
	bw.newLine();
	
	
	bw.newLine();
	bw.write("#----------  extract_nonleaf_nodes:  array with nodes which have degree > "+minDeg+"  ---");
	bw.newLine();
	bw.write("proc extract_nonleaf_nodes{} {"); bw.newLine();
	int nonLeafCount=0;
	for (int i=0; i<nodes.length; ++i) {
	  int deg=0;
	  if ( (deg=g.getNumNeighborsOf(nodes[i])) > minDeg) {
	    bw.write("\tset non_leaf("+nonLeafCount+") "+ nodes[i]+"\t#deg="+ deg);;
	    bw.newLine();
	    ++nonLeafCount;
	  }
	}
	bw.newLine();
	bw.write("}  #end function extract_nonleaf_nodes");
	bw.newLine();
	
	bw.close();
	Util.MSG("... DONE.");
    }


  public static void convert(String briteFile, int format) throws Exception {
    FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, format); 
    Topology t = new Topology(f);
    NSExport ne = new NSExport(t, new File(briteFile+"_NS.tcl"));
    ne.export();
  }
  

  public static void main(String args[]) throws Exception {
    String briteFile = "";
    String routeroras = "";
    try {
      briteFile = args[0];
      routeroras = args[1];
    }
    catch (Exception e) {
      Util.ERR("Usage:  java Export.NSExport <brite-format-file> RT {| AS}");
    }
    
    int format = ModelConstants.RT_FILE;
    if (routeroras.equalsIgnoreCase("as"))
      format = ModelConstants.AS_FILE;
    
    FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, format); 
    
    Topology t = new Topology(f);
    NSExport ne = new NSExport(t, new File(briteFile+"_NS.tcl"));
    ne.export();
    
    
  }
  
}    

