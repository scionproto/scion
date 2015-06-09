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

import Graph.*;
import Util.*;

import java.util.Random; 


/** Derived from class Model, this abstract class serves as a parent
class for models that will ultimately generate router level
topologies.  In this distribution of BRITE, two subclasses,
RouterWaxman and RouterBarabasiAlbert use the functionality provided
in this class.  RouterModel (this class) implements the PlaceNodes()
and AssignBW() functions for router level models.  If you are creating
your own router model, you may use use the functionality provided in
this class, but you are free to derive your class directly from Model.

ASModel is an analogous class for Autonomous System (AS) level topologies.

*/
public abstract class RouterModel extends Model {

    //No constructor because "RouterModel" alone is meaningless.  Use subclass for
    //constructors.

    //Put the stuff that all RouterModels must have in this class.
    /*bandwidth stuff*/
    int bwDist;
    double bwMin, bwMax;
  Random ConnectRandom = rm.CONNECT_NODES();
    

  /** 
      Place nodes of nodeType (router nodes in this case) onto the
      plane according to the NodePlacement type and add them to our
      graph g.  Does collision checking to ensure that two nodes in
      the plane can never have the same (x,y) coords.
      
  */
    public void PlaceNodes(Graph g, int nodeType /*meta or non-meta node*/)  {
      Random PlaceRandom = rm.PLACE_NODES();
	int numSquares = HS/LS;
	int totalSquares = numSquares * numSquares;
	//	Util.MSGN("Placing "+N+" nodes...");
	if (nodePlacement == ModelConstants.NP_RANDOM) { 
	    
	    for (int i=0; i<N; ++i) {
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
		Node n = new Node();
		if (nodeType ==ModelConstants.RT_NODE)
		    n.setNodeConf(new RouterNodeConf(x, y, 0));
		else if (nodeType == ModelConstants.AS_NODE)
		    n.setNodeConf(new ASNodeConf(x,y,0));
		g.addNode(n);
	    }
	}

	else if (nodePlacement == ModelConstants.NP_HEAVYTAILED) {
	    int totalNodes=0;
	    int numNodesToPlace=0;
	    
	    while (totalNodes < N) {
		for (int i=0; i< numSquares; ++i) {
		    for (int j=0; j<numSquares; ++j) { 
			numNodesToPlace = (int) 
(Distribution.getParetoRandom(PlaceRandom, 1000000*LS*LS, 1.0));
			if (numNodesToPlace>LS * LS)
			    numNodesToPlace =LS*LS;
			for (int k=0; k<numNodesToPlace; ++k) {
			   
			    int x = (int) (Distribution.getUniformRandom(PlaceRandom)*LS + j*LS);
			    int y = (int) (Distribution.getUniformRandom(PlaceRandom)*LS + i*LS);
			    
			 
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
			    Node n = new Node();  /*add node to graph*/
			    if (nodeType == ModelConstants.RT_NODE)
				n.setNodeConf(new RouterNodeConf(x, y, 0));
			    else if (nodeType == ModelConstants.AS_NODE)
				n.setNodeConf(new ASNodeConf(x,y,0));
			    g.addNode(n);
			    
			    ++totalNodes;
			    if (totalNodes>=N) break;
			} /*end k loop*/
			if (totalNodes>=N) break; 
		    }/*end j loop */
		    if (totalNodes>=N) break;
		}/*end  i loop */
	    } /*end while*/
	    
	}
	
	else /*node placement is not defined*/
	    {
		Util.ERR("NodePlacement type not found. ");
	
	    }
	
	//g.dumpToOutput();
	//DEBUG] Finished placing nodes.  G has " + g.getNumNodes() + " nodes");
	//return g;
	//	System.out.println("\tDONE.");
    }

  /**
     Assign bandwidth to a graph generated by a router model according to the bwDist parameter passed into RouterModel's subclass. 
   */
    public void AssignBW(Edge[] e) {
      Random BWRandom = rm.BW();
      
      //Util.MSGN("Assigning Edge Bandwidth.."+bwDist);
	
	if (bwDist == ModelConstants.BW_CONSTANT) {
	  for (int i=0; i<e.length; ++i) { 
	      e[i].setBW(bwMin);
	  }
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
	//System.out.println("\tDONE.");
  }
  
  // this serves no function and is an implementation side affect.  should (can) never be called.*/
  // public Graph Generate() { return null; };
    
}















