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
import java.util.HashMap;

/** 
    Functionality to import topologies from NLANR ASConnlist format
    (*.nlanr) back into our data structures.  We use directed edges in
    the graph to represent NLANR topologies. <p>
    
     Generally, all Import routines would be called by the
     Model.FileModel class.  However, if you only need to import the
     Graph and not the Model parameters, you can simply call the
     <code>parse</code> method to obtain the Graph.  The model paramters
     can be access by the <code>getFormatParams</code> method.<p>
     
     All NodeIDs are reinitialized to native BRITE id. A mapping between
     the actual IDs and the new assigned BRITE Ids are stored in a
     hashmap <code> id2id </code> with key as the actual IDs and values
     as the BRITE ids.  You can access this mapping by the
     <code>getIDMap()</code> method.  */

public class NLANRImport {
    private BufferedReader br;
    boolean isAS;
    Graph g; 
    String formatParams=""; 
    HashMap id2id;


    /**
       Class Constructor: Creates a constructor to import either a
       router-level or an AS-level topology from a specified file.
       @param inFile the file to import the topology from
       @param type Either ModelConstants.AS_FILE or ModelConstants.RT_FILE 
    */
    public NLANRImport(File inFile, int type) {
      
	try {
	    br = new BufferedReader(new FileReader(inFile));
	}
	catch (IOException e) {
	    Util.ERR("Error reading from file  " + e);
	}
	if (type == ModelConstants.AS_FILE)
	    isAS=true;
	else isAS=false;
	g = new Graph();
	id2id = new HashMap();
	
    }

  public void convert(String briteFile) {
    Graph g = parse();
    Topology t = new Topology(g);
    BriteExport be = new BriteExport(t, new File(briteFile));
    be.export();
  }

    /**
       When importing the graph structure in the specified topology,
       the actual NodeIDs are reinitialized and converted to BRITE
       IDs.  A mapping with the actual file IDs as keys and the BRITE
       IDs as values is maintained, which this method returns.
       @return HashMap the mapping */
    public HashMap getIDMap() { return  id2id; }
    
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
	Util.MSG("Parsing NLANR format file ");
	StreamTokenizer toker = new NLANRTokenizer(br);
      try {
	toker.nextToken();
	while (toker.ttype != toker.TT_EOF) {
	  parseLine(toker);

	  toker.nextToken();
	}	    
      }
      catch (Exception e) {
	  g.dumpToOutput();
	  System.out.println(id2id.toString());
	  Util.ERR("IO Error at line " + toker.lineno() + ":"+ e.getMessage());
      }
      
      return g;
    }
	    
  private void parseLine(StreamTokenizer t) 
  {
    
    try {
	int fromNodeID = (int) t.nval;
	
	Node fromNode = null;
	/*the node could already be in the graph because it could have been
	  someone else's neighbor earlier on..
	*/
	Integer src = ((Integer)id2id.get(new Integer(fromNodeID)));
	if (g.hasNode(src)) {
	    
	    fromNode = g.getNodeFromID(src.intValue());
	}
	else {
	    fromNode = new Node();
	    if (isAS)   fromNode.setNodeConf(new ASNodeConf());
	    else 	    fromNode.setNodeConf(new RouterNodeConf());

	    id2id.put(new Integer(fromNodeID), new Integer(fromNode.getID()));
	    /*add node*/
	    g.addNode(fromNode);
	}
	
	
	t.nextToken();
	
	/*now add all node n's neighbors*/
	t.nextToken();
	while (t.ttype!=t.TT_EOL) {
	    Node toNode=null;
	    Integer parsedToNodeID= new Integer((int) t.nval);
	    Integer toNodeID = (Integer)id2id.get(parsedToNodeID);
	    if (!g.hasNode(toNodeID)){
	      toNode = new Node();
	      
	      id2id.put(parsedToNodeID, new Integer(toNode.getID()));
	      if (isAS) 
		toNode.setNodeConf(new ASNodeConf());
	      else toNode.setNodeConf(new RouterNodeConf());
	      g.addNode(toNode);
	    }
	    else {
		toNode = g.getNodeFromID(toNodeID.intValue());
	    }
	    Edge e = new Edge(fromNode, toNode);
	    if (isAS) e.setEdgeConf(new ASEdgeConf());
	    else e.setEdgeConf(new RouterEdgeConf()); 
	    e.setDirection(GraphConstants.DIRECTED);
	    g.addEdge(e);
	    
	    t.nextToken();
	}
    }
      catch (IOException e) {
	Util.ERR(" Error importing from NLANR file: " +e);

      }
    }



  //TO DEBUG
      
      public static void main(String args[]) throws Exception  {
	  
	  String filename = args[0];
	  Graph g = null;
	  NLANRImport ni = new NLANRImport(new File(filename), ModelConstants.AS_FILE);
	  g = ni.parse();
	  
	  g.dumpToOutput();
	  
  
   }




}


class NLANRTokenizer extends StreamTokenizer {

    protected NLANRTokenizer(Reader r) {
	super(r);
	eolIsSignificant(true);
	whitespaceChars(':', ':');
	whitespaceChars('-', '-');
	whitespaceChars('>', '>');
	parseNumbers();

    }
 


}








