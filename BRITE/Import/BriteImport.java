/****************************************************************************/
/*                  Copyright 2001, Trustees of Boston University.          */
/*                               All Rights Reserved.                       */
/*                                                                          */
/* Permission to use, copy, or modify this software and its documentation   */
/* for educational and research purposes only and without fee is hereby     */
/* granted, provided that this copyright notice appear on all copies and    */
/* supporting documentation.  For any other uses of this software, in       */
/* original or modified form, including but not limited to distribution in  */
/* whole or in part, specific prior permission must be obtained from Boston */
/* University.  These programs shall not be used, rewritten, or adapted as  */
/* the basis of a commercial software or hardware product without first     */
/* obtaining appropriate licenses from Boston University.  Boston University*/
/* and the author(s) make no representations about the suitability of this  */
/* software for any purpose.  It is provided "as is" without express or     */
/* implied warranty.                                                        */
/*                                                                          */
/****************************************************************************/
/*                                                                          */
/*  Author:     Alberto Medina                                              */
/*              Anukool Lakhina                                             */
/*  Title:     BRITE: Boston university Representative Topology gEnerator   */
/*  Revision:  2.0         4/02/2001                                        */
/****************************************************************************/

package Import;

import Topology.*;
import Model.*;
import Graph.*;
import Export.*;
import Util.*;

import java.io.*;
import java.util.*;

/** 
   Functionality to import topologies that are saved in Brite format
   (*.brite files) back into our data structures.  An explanation of the BRITE format
   can be found in documentation for the BriteExport class or in the
   BRITE user manual at http://www.cs.bu.edu/brite/docs.htm.  <p>
   
   Generally, all Import routines would be called by the
   Model.FileModel class.  However, if you only need to import the
   Graph and not the Model parameters, you can simply call the
   <code>parse</code> method to obtain the Graph.  The model paramters
   can be access by the <code>getFormatParams</code> method.<p>

   All id information for Nodes  are reinitialized to native
   BRITE id. A mapping between the actual IDs and the new assigned
   BRITE Ids are stored in a hashmap <code> id2id </code> with key as
   the actual IDs and values as the BRITE ids.  You can access this
   mapping by the <code>getIDMap()</code> method.  
 
*/

public class BriteImport {
    private BufferedReader br;
    boolean isAS;
    Graph g;
    String formatParams=""; 
    private HashMap id2id;
    
    /**
       Class Constructor: Creates a constructor to import either a
       router-level or an AS-level topology from a specified file.
       @param inFile the file to import the topology from
       @param type Either ModelConstants.AS_FILE or ModelConstants.RT_FILE 
    */
    public BriteImport(File inFile, int type) {
	try {
	    br = new BufferedReader(new FileReader(inFile));
	}
	catch (IOException e) {
	    System.out.println("[BRITE ERROR]: Error reading from file  " + e);
	    System.exit(0);
	}
	if (type == ModelConstants.AS_FILE)
	    isAS=true;
	else isAS=false;
	g = new Graph();
	id2id = new HashMap();
    } 
 
    /**
       When importing the graph structure in the specified topology,
       the actual NodeIDs are reinitialized and converted to BRITE
       IDs.  A mapping with the actual file IDs as keys and the BRITE
       IDs as values is maintained, which this method returns.
       @return HashMap the mapping */
    public HashMap getIDMap() { return id2id; }

    /**
       Model specific parameters if the import file format specifies
       it.  If none exist, "" is returned. 
       @return String  the format specific parameters.
    */
    public String getFormatParams() { return formatParams; }
    
    

    /**
       File parsing is done here.
       @return Graph A BRITE graph containing the topology read in the format.
    */
    public Graph parse() {
	Util.MSG("Parsing BRITE format file");
	try {
	  String firstLine= br.readLine(); //skip first line
	  formatParams=br.readLine();
	  String line="";

	  while ( ! (line.trim().startsWith("Nodes"))) 
	    line = br.readLine();
	  
	  ParseNodes(br);
	  
	  while ( !(line.trim().startsWith("Edges")))  
	    line=br.readLine();
	  
	  
	  ParseEdges(br);

	  br.close();
	}
	catch (IOException e) {
	  Util.ERR("IO Error while importing Brite topology. ", e);
	}
    
	return g;
    }
    


  
  private void ParseNodes(BufferedReader br) throws IOException {
    //Sample Node Line:
    //NodeID  x      y     indeg  outdeg   corrAS     type
    //999	 190	989	14	14	-1	BACKBONE
    String line="";
    while ( (line=br.readLine())!=null) {
      if (line.trim().equals("")) break;
      if (line.trim().startsWith("Edges")) break;
	  
      StringTokenizer t = new StringTokenizer(line);
     
      //parse all node params
      int id =Integer.parseInt(t.nextToken());
      int x = (int) Double.parseDouble(t.nextToken());
      int y = (int) Double.parseDouble(t.nextToken());
      int inDeg = Integer.parseInt(t.nextToken());
      int outDeg = Integer.parseInt(t.nextToken());
      int asID = Integer.parseInt(t.nextToken());
      String typeS = t.nextToken();
      
      
      //now create the node:
      Node n = new Node();
      id2id.put(new Integer(id), new Integer(n.getID()));
      int type=-1;
      if (isAS) {
	if (typeS.equals("AS_LEAF")) type = ModelConstants.AS_LEAF;
	else if (typeS.equals("AS_BORDER")) type = ModelConstants.AS_BORDER;
	else if (typeS.equals("AS_STUB")) type = ModelConstants.AS_STUB;
	else if (typeS.equals("AS_BACKBONE")) type = ModelConstants.AS_BACKBONE;
	else type=ModelConstants.NONE;
	n.setNodeConf(new ASNodeConf(x, y, 0, type));
      }
      else {
	if (typeS.equals("RT_LEAF")) type = ModelConstants.RT_LEAF;
	else if (typeS.equals("RT_BORDER")) type = ModelConstants.RT_BORDER;
	else if (typeS.equals("RT_STUB")) type = ModelConstants.RT_STUB;
	else if (typeS.equals("RT_BACKBONE")) type = ModelConstants.RT_BACKBONE;
	else  type = ModelConstants.NONE;
	n.setNodeConf(new RouterNodeConf(x,y,0, asID, type));
      }  
      //add node to graph
      
      g.addNode(n);
    }
    
  }

    
  private void ParseEdges(BufferedReader br) throws IOException {
    //Sample Edge Line to Parse:
    //ID    src     dst      euc.dist        delay    BW     asSrc    asTo     type            directed
    //158   918	984	215.1883	-1.0	2.0	918	984	AS_BACKBONE_LINK    U
    String line="";
    while ( (line=br.readLine())!=null) {
      StringTokenizer t = new StringTokenizer(line);
      int id = Integer.parseInt(t.nextToken());
      int srcID = Integer.parseInt(t.nextToken());
      int dstID = Integer.parseInt(t.nextToken());
      float eucDist = Float.parseFloat(t.nextToken());
      float delay =Float.parseFloat(t.nextToken());
      float bw = Float.parseFloat(t.nextToken());
      int asSrcID = Integer.parseInt(t.nextToken());
      int asDstID = Integer.parseInt(t.nextToken());
      String typeS = (String) t.nextToken();
      String directed = (String) t.nextToken();
      
      //now create the Edge!
      int src = ((Integer) id2id.get(new Integer(srcID))).intValue();
      int dst =((Integer) id2id.get(new Integer(dstID))).intValue();
      
      Edge e = new Edge(g.getNodeFromID(src), g.getNodeFromID(dst));
      e.setBW(bw);
      e.setEuclideanDist(eucDist);
      int type =-1;
      if (isAS) {
	if (typeS.equals("E_AS_BORDER")) type = ModelConstants.E_AS_BORDER;
	else if (typeS.equals("E_AS_STUB")) type = ModelConstants.E_AS_STUB;
	else if (typeS.equals("E_AS_BACKBONE")) type = ModelConstants.E_AS_BACKBONE;
	else type = ModelConstants.E_AS;
	e.setEdgeConf(new ASEdgeConf(type));
      }
      else {
	if (typeS.equals("E_RT_BORDER")) type = ModelConstants.E_RT_BORDER;
	else if (typeS.equals("E_RT_STUB")) type = ModelConstants.E_RT_STUB;
	else if (typeS.equals("E_RT_BACKBONE")) type = ModelConstants.E_RT_BACKBONE;
	else type = ModelConstants.E_RT;
	e.setEdgeConf(new RouterEdgeConf(delay, type));
      }
      if (directed.equals("D"))
	e.setDirection(GraphConstants.DIRECTED);
      
      g.addEdge(e);
      
    }
    
	
    }

    /* 
	Just to debug
	
	public static void main(String args[]) {
	String fileToRead="init";
	String fileToWrite="";
	try {
	fileToRead= new String(args[0]);
	fileToWrite = new String(args[1]);
	}
	catch (Exception e) { System.out.println(e); System.exit(0); }
	
	BriteImport bi = new BriteImport(new File(fileToRead), ModelConstants.AS_FILE);
	
	Graph g =  bi.parse();
	Topology t = new Topology(g);
	
	
	//BriteExport be = new BriteExport(t, new File(fileToWrite));
	//be.export();
	
	
	}
    */
    
}





class BriteTokenizer extends StreamTokenizer {

    protected BriteTokenizer(Reader r) {
	super(r);
	eolIsSignificant(true);
	wordChars('_', '_');  //to allow for node/edge type fields, since they contain this character
    }
 


}

