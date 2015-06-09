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

package Export;

import Topology.*;
import Graph.*;
import Model.*;
import Util.*;


import java.io.*;
import java.util.Arrays;



/**
   Export.OtterExport provides functionality to export a topology into
   a format recognized by Otter (*.odf file).  Otter is one of CAIDA's
   network topology visualization tools.  Otter's main benefits
   include data independency and versatility.  You can obtain Otter
   from http://www.caida.org/tools/visualization/.
   
   Currently, OtterExport provides the ability to color topologies by
   the following methods: <br>
   <ol> Nodes:  <br>
    <li> By Corresponding AS </li> 
    <li> By Node degree </li>
    <li> By Node Neighborhood sizes </li>
    </ol>
    <ol> Edges: <br>
    <li> By Bandwidth </li>
    <li> By (Euclidean) Distance </li>
   </ol>
 */

public class OtterExport {
    
    private Topology t;
    private BufferedWriter bw;
    /**
       Class Constructor: Returns an OtterExport object which your
       code may keey around for later use.  The constructor does not
       actually write the topology to the file.  You must explicitly
       call <code> export()</code> method of this object in order to
       write to the file.

       @param t the topology object to export
       @param outFile the destination file to write the topology to.

    */
    public OtterExport(Topology t, File outFile) {
	this.t = t;
	try {
	    bw = new BufferedWriter(new FileWriter(outFile));
	}
	catch (IOException e) {
	    Util.ERR(" Error creating BufferedWriter in BriteExport: " + e);
	}
    }

    /**
       Writes the contents of the topology to the destination file in
       a format that is understood by Otter.  */
    public void export() {
	
	Util.MSG("Exporting to Otter...");
	Graph g = t.getGraph();
	//g.dumpToOutput();
	Node[] nodes = g.getNodesArray();
	Arrays.sort(nodes, Node.IDcomparator);
	Edge[] edges = g.getEdgesArray();
	Arrays.sort(edges, Edge.IDcomparator);
	
	try {
	    writeColorValueItems();
	    
	    bw.write("t " + nodes.length);
	    bw.newLine();
	    bw.write("T " + edges.length);
	    bw.newLine();
	    for (int i=0; i<nodes.length; ++i) {
		Node n = nodes[i];
		NodeConf nc = n.getNodeConf();
		int asID = -1;
		if (nc instanceof RouterNodeConf)
		    asID = ((RouterNodeConf)nc).getCorrAS();
		bw.write("N "+ n.getID() + " " + nc.getX() + " " + nc.getY() +  " " +n.getID());
		bw.newLine();
		bw.write("v " + n.getID() + " 0 " + n.getOutDegree()); 
		bw.newLine();
		bw.write("v " + n.getID() + " 1 " + asID);
		bw.newLine();
	    }
	    for (int i=0; i<edges.length; ++i) {
		Edge e = edges[i];
		if (e.getDirection() == GraphConstants.UNDIRECTED) 
		    bw.write("L " );
		else bw.write("l " );
		bw.write( e.getID() + " "+ ((Node) e.getSrc()).getID() + " "+ ((Node)e.getDst()).getID());
		bw.newLine();
		bw.write("V " + e.getID() + " 2 " + e.getBW()+"'"+e.getEuclideanDist()); 
		bw.newLine();
	    }
	    bw.newLine();
	    bw.close();
	}
	catch (Exception e) {
	    Util.ERR("Error exporting to otter (.odf) file. "+ e);
	}
	Util.MSG("... DONE.");
    }

    private void writeColorValueItems() throws IOException {
	bw.write("g 0 d 1 Node Values");	  bw.newLine();
	bw.write("f 0 Degree");                  bw.newLine();
	bw.write("g 1 d 1 Node Classification"); bw.newLine();
	bw.write("f 1 Corresponding AS");         bw.newLine();
	bw.write("g 2 d 2 Edge Values");          bw.newLine();
	bw.write("f 2 Bandwidth'Distance");       bw.newLine();
    }

   
    public static void convert(String briteFile, int format) {
	FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, format); 
	Topology t = new Topology(f);
	OtterExport ne = new OtterExport(t, new File(briteFile+"_otter.odf"));
	ne.export();
    }
  
    
   public static void main(String args[]) {
	String briteFile = "";
	try {
	    briteFile = args[0];
	}
	catch (Exception e) {
	    Util.ERR("Usage:  java Export.OtterExport <brite-format-file>");
	}

	FileModel f = new FileModel(Import.ImportConstants.BRITE_FORMAT, briteFile, ModelConstants.RT_FILE); 
	Topology t = new Topology(f);
	OtterExport ne = new OtterExport(t, new File(briteFile+"_otter.odf"));
	ne.export();
	
	
    }

}



