

package Export;

import Topology.*;
import Model.*;
import Graph.*;
import Util.*;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.*;


/**
   XXX  This is BETA version!
   XXX  Please report bugs to anukool@cs.bu.edu
   XXX  Again, BETA version!

   Creates DML for the SSFNet simulator. Export routines are designed
   with modularity in mind to encourage reuse.
   
   Creates two DML files: <pre> %outputFile%_networks.dml </pre> which
   contains router level topology (routers + links + hosts) and 
   <pre> %outputFile%.dml </pre> which has interconnections between the different
   networks.  Extensively uses provided <pre> dictionary.dml </pre>
   file.  

   
*/

public class DMLExport {
  
  private BufferedWriter mw;
  private BufferedWriter nw;
  private HashMap nodeInterfaces = new HashMap();
 
  private Topology t;
  
  //some global options
  private int startInterface=6;  //first 5 are reserved.
  private boolean isCreateBGPHosts = false; //these haven't been tested yet..
  private boolean isCreateTCPHosts = false;
  String netDefName="";


  public DMLExport(Topology t, File outFile) {
    this.t = t;
    String fileName = outFile.getName();
    fileName = fileName.substring(0, fileName.lastIndexOf('.'));
    netDefName = fileName+"_networks.dml";
    String mainName = fileName+".dml";
    try {
      mw = new BufferedWriter(new FileWriter(new File(mainName)));
      nw= new BufferedWriter(new FileWriter(new File(netDefName)));
    }
    catch (IOException e) {
      Util.ERR(" Error creating BufferedWriter in DMLExport. ", e);
    }
    
  }
  
  private int getInterface(int nid) {
    Integer id = new Integer(nid);
    int freeInterface = startInterface-1;
    if (nodeInterfaces.containsKey(id)) {
      Integer a = (Integer) nodeInterfaces.get(id);
      freeInterface =  a.intValue();
    }
    nodeInterfaces.put(id, new Integer(freeInterface+1));
    return freeInterface+1;
  }
  
  

 
  //////////////////////////////////////////////////////////////////////////////////////////
  ///////////////   Routines for Writing Autonomous System Specific DML ////////////////////
  //////////////////////////////////////////////////////////////////////////////////////////


  
  private void WriteAS(Graph g) {
    Node[] nodes = g.getNodesArray();
    Arrays.sort(nodes, Node.IDcomparator);
    for (int i=0; i<nodes.length; ++i) {
      //first, write this node in AS topology
      WriteASNode(nodes[i]);
      //second, write associated router level topology
      Topology rT = ( (ASNodeConf) nodes[i].getNodeConf()).getTopology();
      if (rT!=null) {
	Graph rG = rT.getGraph();
	WriteRouter(rG, nodes[i], g);
      }
      else {
	WriteRouter(null, nodes[i], g);
      }
    }
    try {
      mw.newLine(); mw.newLine(); 
      mw.write("\t # links connecting the respective AS border routers.");
      mw.newLine(); mw.newLine();
    }
    catch (IOException e) { Util.ERR("", e);}
    Edge[] edges = g.getEdgesArray();	
    Arrays.sort(edges, Edge.SrcIDComparator);
    for (int i=0; i<edges.length; ++i) 
      WriteASEdge(edges[i]);
    
  }

  private void WriteASNode(Node n) {
    //simply write the as node in main.dml.  
    ASNodeConf nc = (ASNodeConf) n.getNodeConf();
    int nid = n.getID() ; 
    try {
      mw.write("\tNet [ id " + nid);    //mw.newLine();
      //mw.write("\t  graphics [ x "+ nc.getX() + " y "+nc.getY() + " z "+nc.getZ() + "] ");
      mw.write("\t  _extends ."+netDefName+".as"+nid+".Net ]");
      mw.newLine();
    }
    catch (Exception e) {
      Util.ERR("error writing AS node" + nid+".", e);
    }
    
  }
  
  
  private void WriteASEdge(Edge e) {
    Node src = e.getSrc();
    Node dst = e.getDst();
    
    int ASFrom=0;
    int ASTo=0;
    int rtFrom = 0;  //border router in ASFrom that actually knows how to route to ASto
    int rtTo = 0;   //border router in ASTo that receives traffic from ASTo
    
    if (src.getNodeConf() instanceof RouterNodeConf && 
	dst.getNodeConf() instanceof RouterNodeConf) {
      ASFrom = ( (RouterNodeConf) src.getNodeConf()).getCorrAS()  ;
      ASTo = ( (RouterNodeConf) dst.getNodeConf()).getCorrAS()   ;
      rtFrom = src.getID() ;
      rtTo = dst.getID() ;
    }
    else {
      ASFrom = src.getID() ;
      ASTo = dst.getID() ;
      rtFrom = 0;  //these will be the default routers
      rtTo = 0;
    }
    
    int fromInterface = getInterface(ASFrom);
    int toInterface = getInterface(ASTo);
    
    try {
      mw.write("\tlink [ attach " + ASFrom +":"+rtFrom+"("+fromInterface+") ");
      mw.write(" attach " + ASTo+":"+rtTo+"("+toInterface+") ");
      if (e.getDirection() == GraphConstants.DIRECTED)
	;  /*TODO!*/
      mw.write(" delay 0.0 ]" /*+ e.getDelay()*/ + 
	       "  #_extends .dictionary.Links.InterASLink ]");
      mw.newLine(); 
    }
    catch (IOException ex) {
      Util.ERR("Error writing edge ("+src+","+dst+"). ", ex);
    }
    
  }

  



  //////////////////////////////////////////////////////////////////////////////////////////
  ///////////////////   Routines for Writing Router Specific DML  //////////////////////////
  //////////////////////////////////////////////////////////////////////////////////////////
  
  
    private void WriteRouter(Graph g, Node asNode, Graph asG) {
    // if asID == -1, means we only have a router topo.  generate dummy as and asign g as its router
    // topology.  write to as0_network  Net and update main.dml also.  
    int asID=-1;
    if (asNode != null) 
      asID = asNode.getID();
    try {
      if (asNode==null) 
	{
	  mw.write("\tNet [ id "+asID+" _extends ."+netDefName+".as0.Net ]" /*we select asID=0*/);
	  mw.newLine();
	}
      if (asID==-1) nw.write("\tas0"+" [  "); 
      else          nw.write("\tas"+asID+" [ ");
      
      nw.newLine();
      nw.write("\t  Net [  ");  nw.newLine();
      nw.write("\t   AS_status boundary"); nw.newLine();
      nw.write("\t   ospf_area 0"); nw.newLine();
    }
    catch (IOException e) {
      Util.ERR("error writing DML for router topology of AS " + asID+".", e);
    }
    
    // if g is null, generate an "empty" topology. i.e. just one border router and exit
    if (g==null) {
      try {
	//Util.MSG("AS " + asID+" has no corresponding router level topology, creating default one-node topology.");
	nw.write("\t  router [ id 0 ");  nw.newLine();
	nw.write("\t   interface [ idrange [from "+startInterface+" to "+(startInterface+asG.getNumNeighborsOf(asNode)-1)+"] ] ");
	nw.write(" # interfaces to connect to neighboring ASs.");
	nw.newLine();
	nw.write("\t   _extends .dictionary.Routers.BorderRouter  ]");
	nw.newLine();
	if (isCreateBGPHosts)
	  nw.write("\t  _extends .dictionary.Traffic.BGP.BGPHost  ");
	else if (isCreateTCPHosts)
	  nw.write("\t  _extends .dictionary.Traffic.TCP.ClientAndServer");
	nw.newLine();
	nw.write("\t ] #end of router-net"); nw.newLine();
	
	nw.write("\t]  #end of as def"); nw.newLine();
	nw.newLine();
      }
      catch (IOException e) {
	Util.ERR(" error writing dml for (null) router topology of AS " + asID+".", e);
      }
      return;
    }
    
    // else,  generate asID_network Net in networks.dml file. 
    // Writing to main.dml is handled in AS.
    Node[] nodes = g.getNodesArray();
    Arrays.sort(nodes, Node.IDcomparator);
    for (int i=0; i<nodes.length; ++i) {
      //only write nodes that belong to this as
      if (asID!=-1 && ((RouterNodeConf)nodes[i].getNodeConf()).getCorrAS()==asID)
	WriteRouterNode(nodes[i], g);
      else if (asID==-1) //then we are writing only a rotuer level topology
	WriteRouterNode(nodes[i], g);
    }
    
    try {
      nw.newLine();	  nw.newLine();
      nw.write("\t #links: ");
      nw.newLine(); nw.newLine();
    }
    catch (IOException ex) { Util.ERR("", ex); }
    
    Edge[] edges = g.getEdgesArray();
    Arrays.sort(edges, Edge.SrcIDComparator);
    for (int i=0; i<edges.length; ++i) {
      if (asID==-1)
	WriteRouterEdge(edges[i]);
      else {
	Node src = edges[i].getSrc();
	Node dst = edges[i].getDst();
	int srcAS = ((RouterNodeConf)src.getNodeConf()).getCorrAS();
	int dstAS = ((RouterNodeConf)dst.getNodeConf()).getCorrAS();
	//write the edge iff atleast one of its end points falls in this AS
	if (srcAS==asID || dstAS==asID)
	  WriteRouterEdge(edges[i]); 
      }
    }
    
    try {
      nw.write("\t ] #end of router-net"); nw.newLine();
      nw.write("\t]  #end of as def"); nw.newLine();
      nw.newLine();
    }
    catch (IOException e) {
      Util.ERR("error writing dml for router topology of AS "+asID+".", e);
    }
  }
  


  
  private void WriteRouterNode(Node n, Graph rtG) {
    RouterNodeConf nc = (RouterNodeConf) n.getNodeConf();
    int nid = n.getID();
    
    //determine if this is a border router
    int asID = nc.getCorrAS();
    Node[] neighbors = rtG.getNeighborsOf(n);
    int ASneighbors=0;
    for (int i=0; i<neighbors.length; ++i) {
      int corrAS = ( (RouterNodeConf) neighbors[i].getNodeConf()).getCorrAS();
      if (corrAS!=asID)
	++ASneighbors;
    }
    
    try {
      nw.write("\t  router [ id  "+(nid )); nw.newLine();
     
      nw.write("\t   interface [idrange [from "+startInterface+" to " + (startInterface+neighbors.length-1)+" ] ]");
      nw.newLine(); 
      
      if (ASneighbors>0) {
	nw.write("\t   _extends .dictionary.Routers.BorderRouter ]");
	nw.newLine();
	if (isCreateBGPHosts)
	  nw.write("\t  _extends .dictionary.Traffic.BGP.BGPHost ");
      }
      else
	nw.write("\t   _extends .dictionary.Routers.SimpleRouter ]");
      
      nw.newLine();
      if (isCreateTCPHosts) 
	nw.write("\t  _extends .dictioanry.Traffic.TCP.ClientAndServer");
      nw.newLine();
      // nw.write("\t  ]");  nw.newLine();
    }
    catch (IOException ex) {
      Util.ERR("Error writing DML for router node "+n+". ", ex); 
    }
    
  }
  
  
  private void WriteRouterEdge(Edge e) {
    int srcID = e.getSrc().getID() ;
    int dstID = e.getDst().getID() ;
    int fromInterface = getInterface(srcID);
    int toInterface = getInterface(dstID);
    
    try {
      nw.write("\t link [attach "+srcID+"("+fromInterface+") " );
      nw.write(" attach "+dstID+"("+toInterface+") ");
      if (e.getDirection() == GraphConstants.DIRECTED)
	;
      nw.write(" delay "+ e.getDelay());
      nw.write(" _extends .dictionary.Links.IntraASLink ]");
      nw.newLine();
    }
    catch (IOException ex) {
      Util.ERR("Error writing edge ("+srcID+","+dstID+"). ", ex);
    }
  }


  

 

  //////////////////////////////////////////////////////////////////////////////////////////
  /////////////////   Routines for Writing Hierarchical Topologies /////////////////////////
  //////////////////////////////////////////////////////////////////////////////////////////

  

  private void WriteHier(Graph rtG) {
    Node[] nodes = rtG.getNodesArray();
    Arrays.sort(nodes, Node.ASIDComparator);
    ArrayList asNodes = new ArrayList();
    int asID = ((RouterNodeConf)nodes[0].getNodeConf()).getCorrAS();
    Node tempASNode = new Node(asID);
    // write router nodes and edges, organized by their corresponding AS
    WriteRouter(rtG, tempASNode, null);
    asNodes.add(tempASNode);
    for (int i=1; i<nodes.length; ++i) {
      int thisASid = ((RouterNodeConf)nodes[i].getNodeConf()).getCorrAS();
      if (thisASid!=asID) { //write router graph for every new AS we see
	asID=thisASid;
	Node aNode = new Node(asID);
	WriteRouter(rtG, aNode, null);
	asNodes.add(aNode);
      } 
    }
    
    //write AS nodes:
    for (int i=0; i<asNodes.size(); ++i) 
      WriteASNode((Node)asNodes.get(i));
    
    //write AS edges:
    Edge[] edges = rtG.getEdgesArray();
    for (int i=0;i<edges.length; ++i) {
      int ASFrom =( (RouterNodeConf) edges[i].getSrc().getNodeConf()).getCorrAS();
      int ASTo =  ( (RouterNodeConf) edges[i].getDst().getNodeConf()).getCorrAS();
      if (ASFrom!=ASTo) 
	WriteASEdge(edges[i]);
    }
  }

  
  private void WriteHeaders() {
    try {
      mw.newLine();
      mw.write("#BRITE topology output to DML"); mw.newLine();
      mw.newLine(); mw.newLine();
      //The following line in the DML file makes certain that our generated DML file is actually a valid DML file.
      mw.write("_schema [ _find .schemas.Net]");   
      mw.newLine(); mw.newLine();
      mw.write("Net [ ");
      mw.newLine();
      mw.write("\tfrequency 1000000000 \t #1 nanosecond time resolution"); mw.newLine();
      mw.write("\trandomstream ["); mw.newLine();
      mw.write("\t   generator \"MersenneTwister\"");  mw.newLine();
      mw.write("\t   stream \"startseed\""); mw.newLine();
      mw.write("\t   reproducibility_level \"timeline\""); mw.newLine();
      mw.write("\t]"); mw.newLine(); mw.newLine(); 
      mw.write("\t#NOTE:  Interfaces 0-"+(startInterface-1)+" are available for custom use.");
      mw.newLine(); mw.newLine();
      
      /** dml header for networks.dml*/
      nw.newLine();
      nw.write("#BRITE topology output to DML");      nw.newLine();
      nw.write("Net definitions go here.");      nw.newLine(); nw.newLine();
      nw.write("#NOTE:  Interfaces 0-"+(startInterface-1)+" are available for custom use.");
      nw.newLine(); nw.newLine();
      nw.write(netDefName+" [ ");  nw.newLine(); nw.newLine();
    }
    catch (IOException e) {
      Util.ERR("Error writing DML headers.", e);
    }
  }
  
  private void WriteFooters() {
    try {
      mw.newLine(); 
      mw.write("] #end of net");
      mw.newLine();
      mw.close();
      nw.newLine();
      nw.write("] #end of net definitions");
      nw.newLine();
      nw.close();
    }
    catch (IOException e) {
      Util.ERR("Error writing DML footers.", e);
    }
  }
  

  /////////////////////////////////////////////////////////////////////////////////////////////////////




  public void export() {
    Util.MSG("Exporting to DML...");
    try {
      WriteHeaders();
      Graph g = t.getGraph();
      if (t.getModel() instanceof RouterModel) 
	  WriteRouter(g,null, null); //asNode set to null to indicate that this is router level only
      else if (t.getModel() instanceof ASModel) 
	  WriteAS(g);
      else  if ( (t.getModel() instanceof BottomUpHierModel) || 
		 (t.getModel() instanceof TopDownHierModel))
	  WriteHier(g);
      else if (t.getModel() instanceof FileModel) {
	  //need to determine if this is a hierarchical topology or what.
	  Node[] nodes = g.getNodesArray();
	  boolean isHier=true;
	  boolean isRT=false;
	  for (int i=0; i<nodes.length; ++i) {
	      try {
		  RouterNodeConf rnc =  (RouterNodeConf) nodes[i].getNodeConf();
		  isRT=true;
		  if (rnc.getCorrAS()==-1) throw new Exception();
	      } catch (Exception e) {  
		  isHier = false;
		  break; 
	      }
	  }
	  Util.DEBUG("is Hier = " + isHier);
	  if (isHier)  WriteHier(g);
	  else {
	      if (isRT)  WriteRouter(g, null, null);
	      else WriteAS(g);
	  }
      }

    
		 
      WriteFooters();
    }
    catch (Exception e) {
      Util.ERR("Exception encountered while generating DML", e);
    }
    Util.MSG("... DONE.");   
  }
   
    public static void convert(String briteFile, int format) {
         // XXXX:  BETA!  CHANGING FORMAT TO RT_FILE BECAUSE OTHERWISE IT DOES NOT WORK!!!!!!!!
	FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, ModelConstants.RT_FILE); 
	Topology t = new Topology(f);
	DMLExport ne = new DMLExport(t, new File(briteFile));
	ne.export();
    }
  
  
  
    public static void main(String args[]) {
      String briteFile = "";
      String routeroras = "";
      try {
	briteFile = args[0];
	routeroras = args[1];
      }
      catch (Exception e) {
	Util.ERR("Usage:  java Export.DMLExport <brite-format-file> RT {|AS}");
      }
      
      int format = ModelConstants.RT_FILE;
      if (routeroras.equalsIgnoreCase("as"))
	format = ModelConstants.AS_FILE;
      
      
      FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, format); 
      Topology t = new Topology(f);
      
      DMLExport de = new DMLExport(t, new File(briteFile));
      de.export();
    }
	    
}






