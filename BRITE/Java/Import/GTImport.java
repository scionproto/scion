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
    Functionality to import topologies that are saved in the GT-ITM
    (*.gtitm files) ALT format into our graph data structure.  We use
    a undirected graph to represent GTITM topologies. (GTITM
    topologies are undirected in the sense that they have double
    directed edges between each pair or neighboring nodes).  This
    class does not know how to transit-stub topologies.  To import
    transit-stub topologies, use the GTTSImport class instead. <p>
   
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

public class GTImport {
    private BufferedReader br;
    Graph g;
    String formatParams=""; 
    boolean isAS;
    private HashMap id2id;
    
    /**
       Class Constructor: Creates a constructor to import either a
       router-level or an AS-level topology from a specified file.
       @param inFile the file to import the topology from
       @param type Either ModelConstants.AS_FILE or ModelConstants.RT_FILE 
    */
    public GTImport(File inFile, int type) {
	try {
	    br = new BufferedReader(new FileReader(inFile));
	}
	catch (IOException e) {
	    Util.ERR("Error reading from file " + e);
	    
	}
        g = new Graph();
	id2id = new HashMap();
	if (type == ModelConstants.AS_FILE)
	    isAS=true;
	else isAS=false;
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
	Util.MSG("Parsing GTITM format file (alt format, non transit-stub)");
	StreamTokenizer toker = new GTTokenizer(br);
	try {
	    toker.nextToken();
	    /*skip the first line*/
	    while (toker.ttype!=toker.TT_EOL) toker.nextToken();
	    
	    /*but keep the second line*/
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

	try {
	    t.nextToken();
	    while (true) {
		int id =(int)t.nval;
		t.nextToken();
		t.nextToken();        //skip "name" field in alt format
		int x = (int) t.nval; 
		t.nextToken();
		int y = (int) t.nval;
		Node n = new Node();
		id2id.put(new Integer(id), new Integer(n.getID()));
		if (isAS)
		    n.setNodeConf(new ASNodeConf(x,y,0));
		else
		    n.setNodeConf(new RouterNodeConf(x,y,0));
		
		g.addNode(n);
		while (t.ttype != t.TT_EOL) 
		    t.nextToken();
		t.nextToken();
		if (t.ttype == t.TT_EOL) break;
		
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
		
		if (isAS)
		    e.setEdgeConf(new ASEdgeConf());
		else e.setEdgeConf(new RouterEdgeConf());
		
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
    
    
 
    

}


class GTTokenizer extends StreamTokenizer {

    protected GTTokenizer(Reader r) {
	super(r);
	eolIsSignificant(true);
	//whitespaceChars('-', '-');
	//whitespaceChars('>', '>');
	//parseNumbers();

    }
 


}

