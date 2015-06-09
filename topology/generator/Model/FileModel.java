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

package Model;

import Import.*;
import Util.*;
import Graph.*;

import java.util.Random;
import java.io.*;

public final class FileModel extends Model {
    
    int format, type;
    String filename;
    String modelParams;   //these are the FileModel params
    String formatParams;  //these are format specific parameters
    int HS, LS, bwDist;
    double  bwMin, bwMax;


  public FileModel(int fileFormat, String filename, int type /*ASorRT*/, int HS, int LS, int BWDist, double BWMin, double BWMax) {
    this.format = fileFormat;
    this.filename = filename;
    this.type = type;
    if (format == ImportConstants.GTITMts_FORMAT && type == ModelConstants.RT_FILE)
      Util.ERR("GTITM-TransitStub can only be imported at AS level (since it has nodes that may contain a router level topology)");
    
    this.HS = HS; this.LS = LS; bwDist = BWDist;
    bwMin = BWMin; bwMax = BWMax;
    
  }
   
  public FileModel(int fileFormat, String filename, int type) {
    this.format = fileFormat;
    this.filename = filename;
    this.type = type;
    bwMin=-1;
    bwMax=-1;
    bwDist=-1;
  }
    
  
    /**
       place this node in the plane, i.e. get an x,y,z coord for this node
     */
    public  void PlaceNode(Node n) {
	Random PlaceRandom = rm.PLACE_NODES();
	int x = (int) ( Distribution.getUniformRandom(PlaceRandom)*HS);
	int y = (int) ( Distribution.getUniformRandom(PlaceRandom)*HS);
	//System.out.print("("+x+", "+y+") ");
	
	/*check for collisions*/
	while (true) {
	    Integer id = new Integer(Util.Encode(x,y));
	    if (nodePositions.contains(id)) {
		x = (int) ( Distribution.getUniformRandom(PlaceRandom)*HS);
		y = (int) ( Distribution.getUniformRandom(PlaceRandom)*HS);
	    }
	    else { 
		nodePositions.add(id);
		break;
	    }
	}
	n.getNodeConf().setCoordinates(x,y,0);
    }




    //Model ( 7 )  format filename bw bwmin bwmax
    public String toString() {
	String fileModelParams = "Model ("+type+" - Imported From ";
	if (format == ImportConstants.GTITM_FORMAT)
	  fileModelParams += "GTITM ";
	else if (format == ImportConstants.BRITE_FORMAT)
	  fileModelParams += "BRITE ";
	else if (format == ImportConstants.NLANR_FORMAT)
	  fileModelParams += "NLANR ";
	else if (format == ImportConstants.SCAN_FORMAT)
	  fileModelParams += "SCAN ";
	else if (format == ImportConstants.INET_FORMAT)
	  fileModelParams += "Inet ";
	else if (format == ImportConstants.SKITTER_FORMAT)
	  fileModelParams += "Skitter ";

	fileModelParams+= "format file "+ filename+" ): " ;
	if (formatParams!=null)
	    return fileModelParams + formatParams;
	else return fileModelParams;
    }

  private void AssignBW(Edge[] e) {
    Random BWRandom = rm.BW();
    if (bwDist == ModelConstants.BW_CONSTANT) {
	for (int i=0; i<e.length; ++i)  
	  e[i].setBW(bwMin);
      
    }
    else if (bwDist == ModelConstants.BW_UNIFORM) {
      for (int i=0; i<e.length; ++i) 
	e[i].setBW(bwMin + bwMax*Distribution.getUniformRandom(BWRandom));
    }
    else if (bwDist == ModelConstants.BW_HEAVYTAILED) {
      for (int i=0; i<e.length; ++i) 
	e[i].setBW(Distribution.getParetoRandom(BWRandom, bwMin, bwMax, 1.2));
    }
    else if (bwDist == ModelConstants.BW_EXPONENTIAL) {
      for (int i=0; i<e.length; ++i) 
	e[i].setBW(Distribution.getExponentialRandom(BWRandom, bwMin)); 
    }
    else {   //default case
      for (int i=0; i<e.length; ++i) 
	e[i].setBW(-1);
    }
  }
 

    public Graph Generate() {
	Util.MSG("Creating topology from input file.");
	Graph g=null;
	if (format == ImportConstants.BRITE_FORMAT) {
	    try {
		BriteImport bi = new BriteImport(new File(filename), type);
		g = bi.parse();
		formatParams = bi.getFormatParams();
	    }
	    catch (Exception e) { 
	      Util.ERR("Error importing topology from file: "+ filename+". ", e);
	    }
	}
	else if (format == ImportConstants.GTITM_FORMAT) {
	    try {
		GTImport gi = new GTImport(new File(filename), type);
		g =  gi.parse();
		formatParams = gi.getFormatParams();
	    }
	    catch (Exception e) {
		Util.ERR("Error importing topology from file: "+ filename+". " + e); 
	    }
	}
	else if (format == ImportConstants.GTITMts_FORMAT) {
	    try {
	      GTTSImport gts = new GTTSImport(new File(filename));
		g =  gts.parse();
		formatParams = gts.getFormatParams();
	    }
	    catch (Exception e) {
		Util.ERR("Error importing topology from file: "+ filename+". " + e); 
	    }
	}
	else if (format == ImportConstants.NLANR_FORMAT) {
	  try {
	      Util.DEBUG("filename = "+filename);
	      NLANRImport ni = new NLANRImport(new File(filename), type);
	      g = ni.parse();
	      Node[] nodes = g.getNodesArray(); 	      /* assign x,y coords to NLANR nodes*/
	      for (int i=0; i<nodes.length; ++i) {
		PlaceNode(nodes[i]);
	      }
	  }
	  catch (Exception e) {
	    Util.ERR("Error importing topology from file: "+filename+". "+e);
	  }
	}
	else if (format == ImportConstants.SCAN_FORMAT) {
	  try {   
	    Util.DEBUG("filename = "+filename);
	    SCANImport mi = new SCANImport(new File(filename), type);
	    g = mi.parse();
	    /* assign x,y coords to NLANR nodes*/
	    //Node[] nodes = g.getNodesArray();
	    //for (int i=0; i<nodes.length; ++i) {
	    // PlaceNode(nodes[i]);
	    //}
	    //  formatParams = ni.getFormatParams();  //NLANR has no format params
	  }
	  catch (Exception e) {
	    Util.ERR("Error importing topology from file: "+filename+". "+e);
	  }
	  
	}
	
       	else if (format == ImportConstants.INET_FORMAT) {
	   try {
	      Util.DEBUG("filename = "+filename);
	      InetImport ii = new InetImport(new File(filename), type);
	      g = ii.parse();
	  
	    //  formatParams = ii.getFormatParams();  //Inet has no format params
	  }
	  catch (Exception e) {
	    Util.ERR("Error importing topology from file: "+filename+". "+e);
	  }

	}
	
	if (bwMin!=-1 || bwMax!=-1 || bwDist!=-1)
	  AssignBW(g.getEdgesArray());
	
	return g;
    }

}










