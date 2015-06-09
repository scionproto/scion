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

import java.util.*;
import java.io.File;
import java.lang.*;           //for Math.floor

public class BottomUpHierModel extends Model {

    Model r;
    int numASNodes;  /*size of AS topology*/
    int groupingMethod;
    int assignType;
    int bwInter;
    double interMax, interMin;
    Random AssignRandom;     // we get this when we need it from our RandomGenManager 
    Random GroupingRandom;
    
    public BottomUpHierModel(Model r, int numASNodes, int groupingMethod, 
			     int asType, int bwInter, double interMin, double interMax)
    {
	this.r = r;
	this.numASNodes = numASNodes;
	this.groupingMethod = groupingMethod;
	this.assignType = asType;
	this.bwInter = bwInter;
	this.interMax = interMax;
	this.interMin = interMin;
	
    	AssignRandom = rm.ASSIGN();
	GroupingRandom = rm.GROUPING();
    }
  
  public int getNumASNodes() { return numASNodes; }
  
    public String toString() { 

	String modelParams = "Model ("+ModelConstants.HI_BOTTOMUP+" - BottomUp): ";
	modelParams += numASNodes + " " + groupingMethod + " " + assignType + " " + bwInter + " " + interMin + " " + interMax + "\n";
	modelParams += r.toString();
	return modelParams;
	    
    }
        
  private int getNodesPerAS(int numGroupedSoFar) {
    int nodesPerAS=0;
    /*return number of nodes according to AssignType*/
    if (assignType == ModelConstants.BU_ASSIGN_CONST)
      nodesPerAS= (int) (N/numASNodes);
    else if (assignType == ModelConstants.BU_ASSIGN_HT) 
	nodesPerAS = (int) (Distribution.getParetoRandom(AssignRandom, 1,  N,  1.2));
    else if (assignType == ModelConstants.BU_ASSIGN_UNIFORM)
	nodesPerAS = (int)(Distribution.getUniformRandom(AssignRandom)* 2.0*N/numASNodes);
    else if (assignType == ModelConstants.BU_ASSIGN_EXP)
	nodesPerAS = (int) (Distribution.getExponentialRandom(AssignRandom, numASNodes/N));

    else 
      Util.ERR("AS Assignment Type " + assignType+ " not found.");

    if (nodesPerAS + numGroupedSoFar >= N)
      return (N-numGroupedSoFar);
        
    //Util.DEBUG("nodesPerAS = " + nodesPerAS);
    return nodesPerAS;
  }

    
    /**
     *  Method:  groupNodes(g0)
     *  -----------------------
     *  Assign routers in g0 an ASid according to our groupingMethod.
     *
     *  A note on assigining IDs:  we don't really create a new Node (waste of memory), we 
     *  simply increment the static int (nodeCount) in the Node class and so are guranteed a unique
     *  ID for the AS "node" that the routers will belong to.
     * 
     *  How Grouping is Done:
     *  ---------------------
     *  RANDOM_PICK:    For each AS node, do the following:  First, determine 
     *  nodesPerAS, the number of routers that will be in this AS (according to the AssignType).  
     *  Second, randomly pick nodesPerAS routers in the router topology assign them to 
     *  this AS (and mark them as unavailable for the other ASs).   Because of the way
     *  routers are assigned to ASs, we could have (should have) disconnected or non-neighbor
     *  routers belonging  to the same AS.
     *
     *  RANDOM_WALK: Start at some router node (picked at random) and
     *  do a random depth first traversal till nodesPerAS nodes are
     *  covered.  Mark all these nodes as belonging to the same AS.
     *  For remaining ASs, continue where the traversal stopped and
     *  
     */
    protected void groupNodes(Graph g0) {
	
      ArrayList g0Nodes = g0.getNodesVector();
      int g0NumNodes = g0.getNumNodes();
     
      
      if (groupingMethod == ModelConstants.BU_RANDOMPICK) {
	/*group nodesPerAS routers into numASNodes*/
	int nodesPerAS = 0;
	int numGroupedSoFar=0;
	for (int i=0; i<numASNodes; ++i) {
	    nodesPerAS = getNodesPerAS(numGroupedSoFar); //(int) (g0NumNodes / numASNodes);
	
	    int ASid = Node.getUniqueID();       /*create a unique id for this AS*/
	    
	    for (int j = 0; j<nodesPerAS; ++j) {
		if (g0Nodes.size()==0)
		    break;
		int indexToRemove = (int) (Distribution.getUniformRandom(GroupingRandom) * (double) g0Nodes.size());
		Node n = (Node) g0Nodes.remove(indexToRemove);   ///remove this node
		((RouterNodeConf)n.getNodeConf()).setCorrAS(ASid);
	      ++numGroupedSoFar;
	    }
	}
      }
      
      
      
      else if (groupingMethod == ModelConstants.BU_RANDOMWALK) {
	  //if (!g0.isConnected())  Util.ERR("but g0 is not connected!!!");
	  g0.markAllNodes(GraphConstants.COLOR_WHITE);  
	  Node[] nodesV  = g0.getNodesArray();
	Stack dfsStack = new Stack();
	
	//select a random node to start dfs from:
	int startRand = (int) (Distribution.getUniformRandom(GroupingRandom)*(double)N);
	Node start = nodesV[startRand];
	start.setColor(GraphConstants.COLOR_BLACK);
	
	dfsStack.push(start);
	int numGroupedSoFar = 0;
	while (numGroupedSoFar < N) {
	  //get another ASID to group the next set of nodes
	  int ASid = Node.getUniqueID();
	  //determine how many routers does this AS have:
	  int nodesPerAS = getNodesPerAS(numGroupedSoFar);
	  int visited=0;   //keep number of visited so far under max nodes this AS can have 
	  while (visited<nodesPerAS) {
	    Node top = (Node) dfsStack.peek();
	    int assignedID= ((RouterNodeConf)top.getNodeConf()).getCorrAS();
	    while (assignedID!=-1 && !dfsStack.isEmpty())    {
		top = (Node) dfsStack.pop();
		assignedID = ((RouterNodeConf)top.getNodeConf()).getCorrAS();
	      }
	    
	    ((RouterNodeConf)top.getNodeConf()).setCorrAS(ASid);
	    ++visited;
	    ++numGroupedSoFar;
	    Node[] neighbors  = g0.getNeighborsOf(top);
	    int newNeighbors=0;
	    for (int i=0; i<neighbors.length; ++i) {  //TODO:  need to randomize this!
	      Node ni = neighbors[i];
	      if (ni.getColor() == GraphConstants.COLOR_WHITE) {
		ni.setColor(GraphConstants.COLOR_BLACK);
		dfsStack.push(ni);
		++newNeighbors;
	      }
	    } //end loop through neighbors
	    if (visited>=nodesPerAS)   break;  //all these should never happen but i'm paranoid
  	    if (dfsStack.isEmpty())    break;
	    if (numGroupedSoFar>=N)    break; 
	  }  //end while visited<nodesPerAS
	  if (dfsStack.isEmpty()) break;
	} // end while numGroupedSoFar < N
	
	//Util.DEBUG("Finished grouping according to Random Walk.  Grouped Nodes="+numGroupedSoFar);
	//Util.DEBUG("dfsStackSize = " + dfsStack.size());
      }
    	
    }

  protected void markEdges(Edge[] e) {
    for (int i=0; i<e.length; ++i) {
      int ASFrom =( (RouterNodeConf) e[i].getSrc().getNodeConf()).getCorrAS();
      int ASTo =  ( (RouterNodeConf) e[i].getDst().getNodeConf()).getCorrAS();
      if (ASFrom!=ASTo) 
	e[i].setEdgeConf(new ASEdgeConf(ModelConstants.E_AS_BORDER));
      
    }
  }

    public void AssignBW(Edge[] e) {
	Random BWRandom = rm.BW();
	if (bwInter == ModelConstants.BW_CONSTANT) {
	    for (int i=0; i<e.length; ++i) {
		int ASFrom =( (RouterNodeConf) e[i].getSrc().getNodeConf()).getCorrAS();
		int ASTo =  ( (RouterNodeConf) e[i].getDst().getNodeConf()).getCorrAS();
		if (ASFrom!=ASTo) 
		    e[i].setBW(interMin);
	    }
	}
	else if (bwInter == ModelConstants.BW_UNIFORM) {
	        for (int i=0; i<e.length; ++i) {
		int ASFrom =( (RouterNodeConf) e[i].getSrc().getNodeConf()).getCorrAS();
		int ASTo =  ( (RouterNodeConf) e[i].getDst().getNodeConf()).getCorrAS();
		if (ASFrom!=ASTo)
		    e[i].setBW(interMin+ Distribution.getUniformRandom(BWRandom)*interMax);
		}
	}
	else if (bwInter == ModelConstants.BW_EXPONENTIAL) {
	    for (int i=0; i<e.length; ++i) {
		int ASFrom =( (RouterNodeConf) e[i].getSrc().getNodeConf()).getCorrAS();
		int ASTo =  ( (RouterNodeConf) e[i].getDst().getNodeConf()).getCorrAS();
		if (ASFrom!=ASTo)
		    e[i].setBW(Distribution.getExponentialRandom(BWRandom, interMin));
	    }
	}
	else if (bwInter == ModelConstants.BW_HEAVYTAILED) { 
	    for (int i=0; i<e.length; ++i) {
		int ASFrom =( (RouterNodeConf) e[i].getSrc().getNodeConf()).getCorrAS();
		int ASTo =  ( (RouterNodeConf) e[i].getDst().getNodeConf()).getCorrAS();
		if (ASFrom!=ASTo)
		    e[i].setBW(Distribution.getParetoRandom(BWRandom, interMin, interMax, 1.2));
	    }
	}
	else { //default case
	    for (int i=0; i<e.length; ++i) {
		int ASFrom =( (RouterNodeConf) e[i].getSrc().getNodeConf()).getCorrAS();
		int ASTo =  ( (RouterNodeConf) e[i].getDst().getNodeConf()).getCorrAS();
		if (ASFrom!=ASTo)
		    e[i].setBW(-1);
	    }
	}
    }

    
    public Graph Generate() {
	
	/*Step 1: Generate router topology*/
	Graph g0 = r.Generate(); //g0 is bottomlevel graph (router)
	N = g0.getNumNodes();

	/*Step 2: Update asID field for each router in g0*/
	Util.MSG("Grouping Nodes...");
	groupNodes(g0);
	
	/*Step 2(b): identify and mark inter as edges*/
	Edge[] g0Edges = g0.getEdgesArray();
	markEdges(g0Edges);
	
	/*Step 3: Update edge bw for inter AS edges*/
	Util.MSG("Assigning Inter AS bandwidth");
	AssignBW(g0Edges);


	return g0;
    }


}
    










