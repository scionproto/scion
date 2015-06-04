/**
   JSimExport takes a brite format file and produces the following data structures:
   1) vertex[][] :  id> networkID x y
   2) edge[][]  : fromnode> tonode length(int) -1/+1  (-1 if link is within network, +1 if not)
   3) network[][]: networkID> node1 node2 node3 node4..
   4) edge_count[]: networkID > number-of-ougoing-links-from-this-network
   6) node_count[]: networkID> number of nodes in the network
   5) node_degree[]: node >  number of links out node
   Once these are produced, we use the xml functions provided in SGB_altToInet.java to output to JSim format. 
*/

package Export;

import java.io.*;
import java.util.*;


import Topology.*;
import Graph.*;
import Model.*;
import Util.*;


public class JSimExport {  
    
    
    private Topology t;
    private PrintWriter out;
    private BufferedReader br;
    
    int numberOfCol = 4;
    int NumVertices;
    int NumEdges;
    int NumNetworks;
    
    HashMap as2network;
    String nameOfTopology="";
    HashMap node2index;
	
    public JSimExport(Topology t, File outFile) {
	this.t = t;
	try {
	    out = new PrintWriter(new FileWriter(outFile));
	}
	catch (IOException e) {
	    Util.ERR("Error creating BufferedWriter in JSimExport: " +e); 
	}
	nameOfTopology = outFile.getName();
    }
    
    public void export()  throws Exception {
	Util.MSG("Producing export file for Javasim ");
	Graph g = t.getGraph();
	
	makeASnum2NetworkID(g);
	
	NumVertices=g.getNumNodes();
	NumEdges=g.getNumEdges();
	NumNetworks = as2network.size();
	
	
	//must be in this order:  first vertices, then everythign else.
	int[][] vertex = makeVertex(g);
	int[][] edge = makeEdges(g);
	int[] node_degree = makeNodeDegree(g);
	
	if ( (t.getModel() instanceof RouterModel) || (t.getModel() instanceof ASModel)) 
	    WriteFlatXML(vertex, edge, node_degree);
	else if ( (t.getModel() instanceof TopDownHierModel) || (t.getModel() instanceof BottomUpHierModel)) {
	    int[][] network = makeNetworks(g);
	    int[] node_count = makeNodeCount(g);
	    int[] edge_count = makeEdgeCount(g);
	    WriteHierXML(vertex, edge, node_degree, node_count, edge_count, network);
	}
	else if (t.getModel() instanceof FileModel) {
	    //need to determine if this is a hierarchical topology or what.
	    Node[] nodes = g.getNodesArray();
	    boolean isHier=true;
	    for (int i=0; i<nodes.length; ++i) {
		try {
		    RouterNodeConf rnc =  (RouterNodeConf) nodes[i].getNodeConf();
		    if (rnc.getCorrAS()==-1) throw new Exception();
		} catch (Exception e) {  
		    isHier = false;
		    break; 
		}
	    }
	    Util.DEBUG("is Hier = " + isHier);
	    if (isHier) {
		int[][] network = makeNetworks(g);
		int[] node_count = makeNodeCount(g);
		int[] edge_count = makeEdgeCount(g);
		WriteHierXML(vertex, edge, node_degree, node_count, edge_count, network);
	    }
	    else 
		WriteFlatXML(vertex, edge, node_degree);
	}
	out.close();
	Util.MSG("... DONE.");
    }
    
    
    private void makeASnum2NetworkID(Graph g) {
	Node[] nodes = g.getNodesArray();
	as2network = new HashMap();
	int netID=0;
	for (int i=0; i<nodes.length; ++i ){
	    NodeConf nc = nodes[i].getNodeConf();
	    Integer asN;
	    try { asN = new Integer(((RouterNodeConf)nc).getCorrAS()); 	    }
	    catch (Exception e) { asN = new Integer(-1);	    }
	    if (!as2network.containsKey(asN)) {
		as2network.put(asN, new Integer(netID));
		++netID;
	    }
	}
    }
    
    public int[][] makeVertex(Graph g) {
	node2index = new HashMap();
	int[][] vertex = new int[g.getNumNodes()][numberOfCol];
	Node[] nodes = g.getNodesArray();
	for (int i=0; i<nodes.length; ++i) {
	    NodeConf nc = nodes[i].getNodeConf();
	    vertex[i][0] = nodes[i].getID();
	    vertex[i][1]= getNet(nodes[i]);
	    vertex[i][2] = nc.getX();
	    vertex[i][3] = nc.getY();
	    node2index.put(nodes[i], new Integer(i));
	}
	return vertex; 
    }
    
  public int[][] makeEdges(Graph g) {
      int[][] edge = new int[g.getNumEdges()][numberOfCol];
      Edge[] gEdges = g.getEdgesArray();
      for (int i=0; i<gEdges.length; ++i) {
      Node src = gEdges[i].getSrc();
      Node dst = gEdges[i].getDst();
      edge[i][0]=getNodeIndex(src); 
      edge[i][1]=getNodeIndex(dst);
      edge[i][2]=(int) gEdges[i].getEuclideanDist();
      if (getNet(src)==getNet(dst)) 
	edge[i][3]=-1;   //intra as link
      else 
	edge[i][3]=1;   //inter as link
    }
    return edge;
  }

    public int[] makeNodeDegree(Graph g) {
    int[] node_degree = new int[NumVertices];
    Node[] nodes = g.getNodesArray();
    for (int i=0; i<nodes.length; ++i ) {
      node_degree[i] = g.getNumNeighborsOf(nodes[i]);
    }
    return node_degree;
  }
  

  private int[] makeEdgeCount(Graph g) {
    Edge[] gEdges = g.getEdgesArray();
    int[] edge_count = new int[NumNetworks];
    for (int j=0; j<edge_count.length; ++j) 
      edge_count[j]=0;
    for (int i=0; i<gEdges.length; ++i) {
      int srcNet = getNet(gEdges[i].getSrc());
      int dstNet= getNet(gEdges[i].getDst());
      if (srcNet!=dstNet) 
	edge_count[srcNet]++;
    }
    return edge_count;
  }
  

  /** number of nodes in each AS*/
  public int[] makeNodeCount(Graph g) {
    Node[] nodes = g.getNodesArray();
    HashMap net2num = new HashMap();
    for (int i=0; i<nodes.length; ++i) {
      Integer netID = new Integer(getNet(nodes[i]));
      if (net2num.containsKey(netID)) {
	int numnodes = ((Integer) net2num.get(netID)).intValue();
	net2num.put(netID, new Integer(numnodes+1));
      }
      else net2num.put(netID, new Integer(1));
    }
    Integer[] keys = (Integer[]) (net2num.keySet()).toArray(new Integer[net2num.size()]);
    Arrays.sort(keys);
    
    int[] node_count = new int[keys.length];
    for (int i=0; i<keys.length; ++i) {
      node_count[i] = ( (Integer)net2num.get(keys[i])).intValue();
    }
    return node_count;
  }
  

  public int[][] makeNetworks(Graph g) {
    Node[] nodes = g.getNodesArray();
    int[][] network = new int[NumNetworks][NumVertices];
    HashMap net2index = new HashMap();
    for (int i=0; i<nodes.length; ++i) {
      int netID = getNet(nodes[i]);
      int lastIndex =0;
      if (net2index.containsKey(new Integer(netID))) 
	lastIndex = ((Integer)net2index.get(new Integer(netID))).intValue();
      network[netID][lastIndex]= getNodeIndex(nodes[i]); 
      net2index.put(new Integer(netID), new Integer(lastIndex+1));
    }
    return network;
  }


  private int getNet(Node n) {
    Integer asN = new Integer(getAS(n));
    //Util.DEBUG(asN+" <<-- asN from getNet");
    if (asN.intValue() == -1) return 0;
    return ((Integer)as2network.get(asN)).intValue();
  }

  private int getAS(Node n) {
      int asN;
      try { 
	  NodeConf nc = n.getNodeConf();
	  asN = ((RouterNodeConf)nc).getCorrAS(); 	       
    }
    catch (Exception e) {      return -1;     }
      return asN;
  }

    private int getNodeIndex(Node node) {
	if (node2index.containsKey(node)) 
	    return ( (Integer)node2index.get(node)).intValue();
	//else we're in trouble.
	//Util.DEBUG("no index found for node " + node+" . assigning -1");
	return -1;
    }
  
  
  public void WriteFlatXML(int[][] vertex, int[][] edge, int[] node_degree) throws IOException {  	
      //Util.DEBUG("writing flat!");
    //header
    out.println("<?xml version=\"1.0\"?>\n");
    //topology
    out.println("<node name=\"" + nameOfTopology + "\" class=\"drcl.comp.Component\">\n");
    
    //node
    for (int m = 0; m < NumVertices; m++) {
      out.println("\t<node name=\"node" + vertex[m][0]  + "\" class=\"drcl.inet.Node\" posX=\"" + vertex[m][2]*10 
		  + "\" posY=\"" +  vertex[m][3]*10 + "\">");
      for (int n = 0; n < node_degree[m]; n++)   //port
   	out.println("\t\t<port name=\""+ n +"\" group=\"\"></port>");
      out.println("\t</node>\n");
    }
    
    //link
     for (int ll = 0; ll < NumEdges; ll++) {
       int x = (vertex[edge[ll][0]][2]*10 + vertex[edge[ll][1]][2]*10)/2;
       int y = (vertex[edge[ll][0]][3]*10 + vertex[edge[ll][1]][3]*10)/2;
       out.println("\t<node name=\"link" + ll + "\" class=\"drcl.inet.Link\" posX=\"" + x 
		   + "\" posY=\"" + y  + "\">");
       out.println("\t\t<property name=\"propDelay\" value=\"" + edge[ll][2] 
		   + "\"></property>");
       out.println("\t\t<port name=\""+ 0 +"\" group=\"\"></port>");
       out.println("\t\t<port name=\""+ 1 +"\" group=\"\"></port>");
       out.println("\t</node>\n");
     }
     //connection
     for (int ll = 0; ll < NumEdges; ll++) {
       node_degree[edge[ll][0]]--;
       node_degree[edge[ll][1]]--;
       out.println("\t<connection node1=\"node" + edge[ll][0] 
		   + "\" port1=\""+ node_degree[edge[ll][0]] 
		   + "@\" node2=\"link" + ll 
		   + "\" port2=\"0@\">");
       out.println("\t</connection>\n");
       out.println("\t<connection node2=\"node" + edge[ll][0] 
		   + "\" port2=\""+ node_degree[edge[ll][0]] 
		   + "@\" node1=\"link" + ll 
		   + "\" port1=\"0@\">");
       out.println("\t</connection>\n");
       out.println("\t<connection node1=\"node" + edge[ll][1] 
		   + "\" port1=\""+ node_degree[edge[ll][1]] 
		   + "@\" node2=\"link" + ll 
		   + "\" port2=\"1@\">");
       out.println("\t</connection>\n");
       out.println("\t<connection node2=\"node" + edge[ll][1] 
		   + "\" port2=\""+ node_degree[edge[ll][1]] 
		   + "@\" node1=\"link" + ll 
		   + "\" port1=\"1@\">");
       out.println("\t</connection>\n");
     }
     out.println("</node>\n");
   }
  

  
  
  public void WriteHierXML(int[][] vertex, int[][] edge, int[] node_degree,
				 int[] node_count, int[] edge_count, int[][] network) throws IOException {  	

    /*AL: got this from SGB_altToInet.java - its needed here because things are modified
     in the original edge_count.  I don't know why. */
    int[] edge_count2 = new int[NumNetworks];
    System.arraycopy(edge_count, 0, edge_count2, 0, NumNetworks);
	   
    //Util.DEBUG("writing hier!");
    //header
    out.println("<?xml version=\"1.0\"?>\n");
    //topology
    out.println("<node name=\"" + nameOfTopology + "\" class=\"drcl.comp.Component\">\n");
    
    for (int nn = 0; nn < NumNetworks; nn++) {   //network domain
      out.println("\t<node name=\"network" + nn
		  + "\" class=\"drcl.inet.Network\" posX=\"" 
		  + vertex[network[nn][0]][2]*10 
		  + "\" posY=\"" +  vertex[network[nn][0]][3]*10 + "\">\n");
      
      for (int m = 0; m < node_count[nn]; m++) {   //node
	out.println("\t\t<node name=\"node" + vertex[network[nn][m]][0] 
		    + "\" class=\"drcl.inet.Node\" posX=\"" 
		    + vertex[network[nn][m]][2]*10 
		    + "\" posY=\"" +  vertex[network[nn][m]][3]*10 + "\">");
	
	for (int n = 0; n < node_degree[network[nn][m]]; n++)  //port for node
	  out.println("\t\t\t<port name=\""+ n +"\" group=\"\"></port>");
	out.println("\t\t</node>\n");
      }
      
      for (int m = 0; m < edge_count[nn]; m++)   //port for network
	out.println("\t\t<port name=\""+ m +"\" group=\"\"></port>\n");
      
      for (int ll = 0; ll < NumEdges; ll++) {
	if ((vertex[edge[ll][0]][1] == nn) || (vertex[edge[ll][1]][1] == nn)) {
	  if (edge[ll][3] == -1) { 
	    // link inside the network
	    // link is put at the mid point of two nodes
	    int x = (vertex[edge[ll][0]][2]*10 + vertex[edge[ll][1]][2]*10)/2;
	    int y = (vertex[edge[ll][0]][3]*10 + vertex[edge[ll][1]][3]*10)/2;
	    out.println("\t\t<node name=\"link" + ll  
			+ "\" class=\"drcl.inet.Link\" posX=\"" + x 
			+ "\" posY=\"" + y  + "\">");
	    out.println("\t\t\t<property name=\"propDelay\" value=\"" 
			+ edge[ll][2] 
			+ "\"></property>");
	    out.println("\t\t\t<port name=\""+ 0 +"\" group=\"\"></port>");
	    out.println("\t\t\t<port name=\""+ 1 +"\" group=\"\"></port>");
	    out.println("\t\t</node>\n");
	    
	    // connection between nodes inside the network
	    node_degree[edge[ll][0]]--;
	    node_degree[edge[ll][1]]--;
	    out.println("\t\t<connection node1=\"node" + edge[ll][0] 
			+ "\" port1=\""+ node_degree[edge[ll][0]] 
			+ "@\" node2=\"link" + ll 
			+ "\" port2=\"0@\">");
	    out.println("\t\t</connection>\n");
	    out.println("\t\t<connection node2=\"node" + edge[ll][0] 
			+ "\" port2=\""+ node_degree[edge[ll][0]] 
			+ "@\" node1=\"link" + ll 
			+ "\" port1=\"0@\">");
	    out.println("\t\t</connection>\n");
	    out.println("\t\t<connection node1=\"node" + edge[ll][1] 
			+ "\" port1=\""+ node_degree[edge[ll][1]] 
			+ "@\" node2=\"link" + ll 
			+ "\" port2=\"1@\">");
	    out.println("\t\t</connection>\n");
	    out.println("\t\t<connection node2=\"node" + edge[ll][1] 
			+ "\" port2=\""+ node_degree[edge[ll][1]] 
			+ "@\" node1=\"link" + ll 
			+ "\" port1=\"1@\">");
	    out.println("\t\t</connection>\n");
	  } else { 
	    // link between node and network
	    int x = (vertex[edge[ll][0]][2]*10 + vertex[edge[ll][1]][2]*10)/2;
	    int y = (vertex[edge[ll][0]][3]*10 + vertex[edge[ll][1]][3]*10)/2;
	    out.println("\t\t<node name=\"link" + ll
			+ "\" class=\"drcl.inet.Link\" posX=\"" + x 
			+ "\" posY=\"" + y  + "\">");
	    out.println("\t\t\t<property name=\"propDelay\" value=\"" 
			+ edge[ll][2]/3.0 
			+ "\"></property>");
	    out.println("\t\t\t<port name=\""+ 0 +"\" group=\"\"></port>");
	    out.println("\t\t\t<port name=\""+ 1 +"\" group=\"\"></port>");
	    out.println("\t\t</node>\n");
	    
	    // connection between node and network
	    if (vertex[edge[ll][0]][1] == nn) {
	      node_degree[edge[ll][0]]--;
	      edge_count[nn]--;
	      out.println("\t\t<connection node1=\"node" + edge[ll][0] 
			  + "\" port1=\""+ node_degree[edge[ll][0]] 
			  + "@\" node2=\"link" + ll 
			  + "\" port2=\"0@\">");
	      out.println("\t\t</connection>\n");
	      out.println("\t\t<connection node2=\"node" + edge[ll][0] 
			  + "\" port2=\""+ node_degree[edge[ll][0]] 
			  + "@\" node1=\"link" + ll 
			  + "\" port1=\"0@\">");
	      out.println("\t\t</connection>\n");
	      out.println("\t\t<connection node1=\"."
			  + "\" port1=\""+ edge_count[nn] 
			  + "@\" node2=\"link" + ll 
			  + "\" port2=\"1@\">");
	      out.println("\t\t</connection>\n");
	      out.println("\t\t<connection node2=\"."
			  + "\" port2=\""+ edge_count[nn] 
			  + "@\" node1=\"link" + ll 
			  + "\" port1=\"1@\">");
	      out.println("\t\t</connection>\n");
	    } else if (vertex[edge[ll][1]][1] == nn) {
	      node_degree[edge[ll][1]]--;
	      edge_count[nn]--;
	      out.println("\t\t<connection node1=\"node" + edge[ll][1] 
			  + "\" port1=\""+ node_degree[edge[ll][1]] 
			  + "@\" node2=\"link" + ll 
			  + "\" port2=\"0@\">");
	      out.println("\t\t</connection>\n");
	      out.println("\t\t<connection node2=\"node" + edge[ll][1] 
			  + "\" port2=\""+ node_degree[edge[ll][1]] 
			  + "@\" node1=\"link" + ll 
			  + "\" port1=\"0@\">");
	      out.println("\t\t</connection>\n");
	      out.println("\t\t<connection node1=\"."
			  + "\" port1=\""+ edge_count[nn] 
			  + "@\" node2=\"link" + ll 
			  + "\" port2=\"1@\">");
	      out.println("\t\t</connection>\n");
	      out.println("\t\t<connection node2=\"."
			  + "\" port2=\""+ edge_count[nn] 
			  + "@\" node1=\"link" + ll 
			  + "\" port1=\"1@\">");
	      out.println("\t\t</connection>\n");
	    }
	  }
	}
      }
      
      out.println("\t</node>\n");
    }  // end of network domain
    
    for (int ll = 0; ll < NumEdges; ll++) {
      if (edge[ll][3] != -1) { 
	// link between networks
	int x = (vertex[edge[ll][0]][2]*10 + vertex[edge[ll][1]][2]*10)/2;
	int y = (vertex[edge[ll][0]][3]*10 + vertex[edge[ll][1]][3]*10)/2;
	out.println("\t<node name=\"link" + ll  
		    + "\" class=\"drcl.inet.Link\" posX=\"" + x 
		    + "\" posY=\"" + y  + "\">");
	out.println("\t\t<property name=\"propDelay\" value=\"" + edge[ll][2]/3.0 
		    + "\"></property>");
	out.println("\t\t<port name=\""+ 0 +"\" group=\"\"></port>");
	out.println("\t\t<port name=\""+ 1 +"\" group=\"\"></port>");
	out.println("\t</node>\n");
	
	//connection between networks
	edge_count2[vertex[edge[ll][0]][1]]--;
	edge_count2[vertex[edge[ll][1]][1]]--;
	out.println("\t<connection node1=\"network" + vertex[edge[ll][0]][1]
		    + "\" port1=\""+ edge_count2[vertex[edge[ll][0]][1]]
		    + "@\" node2=\"link" + ll 
		    + "\" port2=\"0@\">");
	out.println("\t</connection>\n");
	out.println("\t<connection node2=\"network" + vertex[edge[ll][0]][1]
		    + "\" port2=\""+ edge_count2[vertex[edge[ll][0]][1]]
		    + "@\" node1=\"link" + ll 
		    + "\" port1=\"0@\">");
	out.println("\t</connection>\n");
	out.println("\t<connection node1=\"network" + vertex[edge[ll][1]][1]
		    + "\" port1=\""+ edge_count2[vertex[edge[ll][1]][1]]
		    + "@\" node2=\"link" + ll 
		    + "\" port2=\"1@\">");
	out.println("\t</connection>\n");
	out.println("\t<connection node2=\"network" + vertex[edge[ll][1]][1]
		    + "\" port2=\""+ edge_count2[vertex[edge[ll][1]][1]]
		    + "@\" node1=\"link" + ll 
		    + "\" port1=\"1@\">");
	out.println("\t</connection>\n");
      }
    }	
    
    out.println("</node>\n");
  }
    
    
    
    public static void convert(String briteFile, int format) throws Exception  {
	FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, format); 
	Topology t = new Topology(f);
	JSimExport ne = new JSimExport(t, new File(briteFile+"_jsim.xml"));
	ne.export();
    }
  


  public static void main(String args[]) throws Exception {
    String briteFile = "";
    String routeroras="";
    try {
      briteFile = args[0];
      routeroras=args[1];
    }
    catch (Exception e) {
      Util.ERR("Usage:  java Export.JSimExport <brite-format-file> RT {|AS}");
    }
    int format = ModelConstants.RT_FILE;
    if (routeroras.equalsIgnoreCase("as"))
	format = ModelConstants.AS_FILE;
    
      
    FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, format);
    Topology t = new Topology(f);
    // BriteExport be = new BriteExport(t, new File(briteFile+"_backToBrite.brite"));
    //be.export();
    //System.out.println("done with be");
    JSimExport je = new JSimExport(t, new File(briteFile+"_jsim.xml"));
    je.export();
    
    
  }
  


}






