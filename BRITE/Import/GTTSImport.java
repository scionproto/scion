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
   Functionality to import topologies that are saved as GT-ITM's
   Transit-Stub alt format (*.gtts files) into our data structures.
   Because GT-ITM's transit-stub format defines a neat grouping of
   router-nodes, we treat each grouping as a distinct AS (either a
   transit-AS or a stub-AS) and thus can assign each router node an
   ASid (that is the ID of the AS node it belong to).  Also, like
   GTImport, we treated GTITM topologies as an undirected graph.
   (GTITM topologies are undirected in the sense that they have double
   directed edges between each pair or neighboring nodes).  This class
   does not know how to import GT-ITM topologies that are flat (that
   is, <code> geo </code> generated topologies.) To import these
   topologies, use the GTImport class instead. <p>

   Generally, all Import routines would be called by the
    Model.FileModel class.  However, if you only need to import the
    Graph and not the Model parameters, you can simply call the
    <code>parse</code> method to obtain the Graph.  The model paramters
    can be access by the <code>getFormatParams</code> method.<p>
    
    All NodeIDs are reinitialized to native BRITE id. A mapping between
    the actual IDs and the new assigned BRITE Ids are stored in a
    hashmap <code> id2id </code> with key as the actual IDs and values
    as the BRITE ids.  You can access this mapping by the
    <code>getIDMap()</code> method.
    
*/
public class GTTSImport {
    private BufferedReader br;
    Graph g;
    String formatParams=""; 
    int NodeNum=0; 
    int EdgeNum = 0;
    private HashMap id2id;

    /**
       Class Constructor: Creates a constructor to import router-level
       topologies only.  (AS level topologies do not make sense for
       the transit-stub format)
       @param inFile the file to import the topology from
    */
    public GTTSImport(File inFile) {
	try {
	    br = new BufferedReader(new FileReader(inFile));
	}
	catch (IOException e) {
	    Util.ERR("Error reading from file " + e);
	    
	}
        g = new Graph();
	id2id = new HashMap();
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
    

  public void convert(String briteFile) {
    Graph g = parse();
    Topology t = new Topology(g);
    BriteExport be = new BriteExport(t, new File(briteFile));
    be.export();
  }
    
    /**
       File parsing is done here.
       @return Graph A BRITE graph containing the topology read in the format.
    */
    public Graph parse() {
	Util.MSG("Parsing GTITM file (ALT format, transit-stub) ");
	StreamTokenizer toker = new GTTSTokenizer(br);
	try {
	    toker.nextToken();
	    /*skip the first line*/
	    while (toker.ttype!=toker.TT_EOL) toker.nextToken();
	    
	    /*first number is number of nodes, second number
		is number of edges.  keep this*/
	    toker.nextToken();
	    NodeNum =(int)  toker.nval;
	    toker.nextToken();
	    EdgeNum = (int) toker.nval;
	    //    Util.DEBUG("numNodes = " +NodeNum+" numEdges = " + EdgeNum);
	    formatParams+=NodeNum+" "+EdgeNum+" ";
	      
	    /*but keep the second line as part of formatParams (so that
	      our Model.toString() method can use it*/
	    while (toker.ttype!=toker.TT_EOL) {
	      if (toker.ttype == toker.TT_WORD)
		    formatParams+=toker.sval;
	      else 
		formatParams+=toker.nval;
	      formatParams+=" ";
	      toker.nextToken();
	    }
	    /*now parse vertices & edges*/
	    while (toker.ttype!=toker.TT_EOF) {
		if (toker.ttype==toker.TT_WORD) {
		    if (toker.sval.equals("VERTICES")) {
			/*skip to end of line*/
			while (toker.ttype != toker.TT_EOL) 
			    toker.nextToken();
			/*now call node parser*/
			ParseNodes(toker);
		    }
		    else if (toker.sval.equals("EDGES")) {
			/*skip to end of line*/
			while (toker.ttype != toker.TT_EOL) 
			    toker.nextToken();
			/*now call edge parser*/
			ParseEdges(toker);
		    }
		}
		toker.nextToken();
	    }
	    br.close();
	}
	catch (IOException e) {
	    Util.ERR("IO Error at line: " + toker.lineno() + " :" +e.getMessage());
	}

	/*build topology here */
	//g.dumpToOutput();
	//	t = new Topology(g);
	return g;
    }


    private void ParseNodes(StreamTokenizer t) {
     
      int lastTransitAS = 0;
      int lastStubAS = -1;
      int lastTP=-1, lastTS=-1;  //helper variables to group stub nodes into an AS
      int ASid=-1;
      try {
	t.nextToken();
	while (true) {
	  //parse line by line until we reach a blank line and then bail out
	  if (t.ttype == t.TT_EOL) 
	    break;
	  int id = (int) t.nval;  //node ID
	  t.nextToken();

	  if (((String)t.sval).equals("T")) { /*** PARSE A TRANSIT NODE***/
	    t.nextToken();  //skip the ':'
	    t.nextToken();
	    //figure out which AS this node corresponds to
	    String transitID = Double.toString(t.nval);  //the id.  eg: 0.1
	    int i = transitID.indexOf('.');
	    String prefix = transitID.substring(0, i); 
	    int a = Integer.parseInt(prefix);
	    if (a!=lastTransitAS)
	      lastTransitAS = a;
	    ASid = lastTransitAS;
	  }
	  else {  /*** PARSE A STUB NODE ***/
	    //We are about to see a line that looks like:
	    //   :2.9/0.7 60 153   (we stop after the 0.7 in this else branch)
	    t.nextToken();  //skip the ':' 
	    t.nextToken();
	    String transitID = Double.toString(t.nval); //first id.  eg: 1.1
	    t.nextToken(); //skip the '/'
	    t.nextToken();
	    String stubID = Double.toString(t.nval);  //the second id: eg: 2.2
	    int i = transitID.indexOf('.');
	    int transitP= Integer.parseInt(transitID.substring(0,i));  //prefix
	    int transitS = Integer.parseInt( transitID.substring(i+1)); //suffix
	    //figure out which AS this node corresponds to:
	    i = stubID.indexOf('.');
	    int a = Integer.parseInt(stubID.substring(0,i));
	    // Util.DEBUG("transit prefix = " + transitP + " transit suffix = " + transitS + " stub as = " +a);
	    //Util.DEBUG("last transit p = " + lastTP   + " last transit s = " + lastTS +   " last stubas = "+lastStubAS);
	    
	    if (a!=lastStubAS || transitP != lastTP || transitS!=lastTS) {
	      lastStubAS =a;
	      lastTP = transitP;
	      lastTS = transitS;
	      ASid = Node.getUniqueID();
	    }
	    
	  }
	    
	  t.nextToken();
	  int x = (int) t.nval;
	  t.nextToken();
	  int y = (int) t.nval;
	  t.nextToken();
	  //	  Util.DEBUG("id =" + id + " x=" + x+" y="+y+" asID="+ASid);
	  
	  RouterNodeConf r = new RouterNodeConf(x, y, 0,ASid);
	  Node n = new Node();
	  id2id.put(new Integer(id), new Integer(n.getID()));
	  n.setNodeConf(r);
	
	  g.addNode(n);    
	  if (t.ttype == t.TT_EOL) {
	    // System.out.println("\n");
	    t.nextToken();
	  }

	  
	}
	
      }    
		
	
	catch (IOException e) {
	    Util.ERR("IO Error at line: " + t.lineno()+ " :" +e.getMessage());
	}
    }
    
    private void ParseEdges(StreamTokenizer t) {
	

	try {
	    t.nextToken();
	    while (true) {
		int srcID = (int) t.nval;
		t.nextToken();
		int dstID = (int) t.nval;
	
		int src = ((Integer) id2id.get(new Integer(srcID))).intValue();
		int dst =((Integer) id2id.get(new Integer(dstID))).intValue();
		Edge e = new Edge(g.getNodeFromID(src), g.getNodeFromID(dst));
		
		
		
		e.setEdgeConf(new RouterEdgeConf());
		
		g.addEdge(e);
		while (t.ttype!=t.TT_EOL)
		    t.nextToken(); 
		t.nextToken(); /*next line*/
		if (t.ttype == t.TT_EOF || t.ttype == t.TT_EOL)
		    break;
	    }
	}

	catch (IOException e) {
	    Util.ERR("IO Error at line: " + t.lineno() + " :" + e.getMessage());
	}
	
    }

  public static void main(String args[]) {
    String filename = args[0];
    GTTSImport g = new GTTSImport(new File(filename));
    Graph h = g.parse();
   
  }
    
    
 
    

}


class GTTSTokenizer extends StreamTokenizer {

    protected GTTSTokenizer(Reader r) {
	super(r);
	eolIsSignificant(true);
	ordinaryChar('/');
	
 	
	
	//whitespaceChars(':', ':');
	//whitespaceChars('.', '.');
	//whitespaceChars('/', '/');
	//ordinaryChars('/', '/');
	//whitespaceChars('-', '-');
	//whitespaceChars('>', '>');
	//parseNumbers();

    }
 


}


