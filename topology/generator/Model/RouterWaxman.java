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
import java.lang.*;
import java.util.*;


/**

 RouterWaxman implements a model by Waxman on router level topology.
 ASWaxman implements an analogous model on Autonomous System (AS)
 level topologies.  Please see the class ASWaxman for documentation.
 These models are very similar on both the router and the AS level.



*/
public final class RouterWaxman extends RouterModel {
    
   double alpha, beta;
    
   
    public RouterWaxman(int N,int HS, int LS, int nodePlacement,
			int m, double alpha, double beta, 
			int growthType, int bwDist, 
			double bwMin, double bwMax) 
    {
	this.N = N;
	this.alpha = alpha; this.beta = beta;
	this.HS = HS; this.LS = LS;
    	this.nodePlacement= nodePlacement;
	this.growthType = growthType;
	this.m = m;
	this.bwDist = bwDist;
	this.bwMin = bwMin;
	this.bwMax = bwMax;
    }
    
    public String toString() { 
	String modelParams = "Model ("+ModelConstants.RT_WAXMAN+" - RTWaxman):  ";
	modelParams += N+" " + HS + " " + LS + " " + nodePlacement + "  " + m + "  ";
	modelParams += alpha + " " + beta + " " + growthType + " " + bwDist + " ";
	modelParams += bwMin+ " " + bwMax + " \n";
	return modelParams;
    }

    private double getEdgeProb(Node src, Node dst) {
	
	int x1 =   (src.getNodeConf()).getX();
	int y1 =   (src.getNodeConf()).getY();
	int x2 =   (dst.getNodeConf()).getX();
	int y2 =   (dst.getNodeConf()).getY();
	int diffX = x1 -x2;
	int diffY = y1-y2;
	double d = (double) Math.sqrt(diffX*diffX + diffY*diffY);
	double L = (double)Math.sqrt(2.0) * HS;
	return (double) (alpha *  Math.exp(-1.0 * (d/(beta*L))));
    }
    
    public void ConnectNodes(Graph g) {
      Util.MSG("Connecting Nodes...");
	
	int N = g.getNumNodes();
	Node[] nodesV = g.getNodesArray();

	if (growthType == ModelConstants.GT_ALL) {
	    int numNodesConnected = 0;
	    int edgeCount=0;
	    while (numNodesConnected < N) {
		int rand1 = (int)  (Distribution.getUniformRandom(ConnectRandom) * N);
		Node src = nodesV[rand1]; //g.getKthNode(rand1);
		int numEdgesAdded = 0;
	
		while (numEdgesAdded < m || numNodesConnected < N) {
		    int rand2 = (int)  (Distribution.getUniformRandom(ConnectRandom) * N);
		    Node dst = nodesV[rand2]; 
		    if (rand1 == rand2) continue;        //no self loops
		    if (g.hasEdge(src, dst)) continue; //no multiedges
		    double p = getEdgeProb(src, dst);
		    double u = (double)Distribution.getUniformRandom(ConnectRandom);
		    if (u < p){
			Edge e = new Edge(src, dst);
			e.setEdgeConf(new RouterEdgeConf());
			g.addEdge(e);
			if (src.getOutDegree() == 1) 
			    ++numNodesConnected;
			if (dst.getOutDegree() == 1)
			    ++numNodesConnected;
			++numEdgesAdded;
		    }
		}		    
	    }
	    
	    
	} /*end GT_ALL*/
	
	else if (growthType == ModelConstants.GT_INCREMENTAL) {
	    for (int i = m; i<N; ++i) {
		Node src = nodesV[i]; 
		int numEdgesAdded=0;
		while (numEdgesAdded < m) {
		    if (src.getOutDegree() >= (N-m)) break;
		       
		    int rand = (int)  (Distribution.getUniformRandom(ConnectRandom) * i);
		    Node dst = nodesV[rand];
		    if (i==rand) continue;
		    if (g.hasEdge(src, dst)) continue;
		    double p = getEdgeProb(src, dst);
		    if (Distribution.getUniformRandom(ConnectRandom) < p) {
			Edge e = new Edge(src, dst);
			e.setEdgeConf(new RouterEdgeConf());
			g.addEdge(e);
			++numEdgesAdded;
			//Util.DEBUG("added edge:("+src.getID()+", "+dst.getID()+")  | numEdgesAdded="+numEdgesAdded);
		    }
		}
		
	    }
	    
	    for (int i=0; i<m; ++i) {
	
		Node src =  nodesV[i]; 
		int numEdgesAdded =0;
		while (numEdgesAdded  < m) {
		    if (src.getOutDegree() >= (N-m)) break;

		    int rand = m+(int)  (Distribution.getUniformRandom(ConnectRandom)* (double) (N-m)); /*pick rand b/w m..N*/
		    Node dst = nodesV[rand];
		    if (i==rand) continue; 
		    if (g.hasEdge(src, dst)) continue;
		   
		    double p = getEdgeProb(src, dst);
		    if (Distribution.getUniformRandom(ConnectRandom) < p) {
			Edge e = new Edge(src, dst);
			e.setEdgeConf(new RouterEdgeConf());
			g.addEdge(e);
			++numEdgesAdded;
			//Util.DEBUG("added edge:("+src.getID()+", "+dst.getID()+")  | numEdgesAdded="+numEdgesAdded);
		    }
		}
	    }
	}	 /*end GT_INCREMENTAL*/
	else { 
	  Util.ERR("Growth Type not found.");
	   
	}
    }

    public Graph Generate() {
      //System.out.println("Generating " + N + " node graph with " + nodePlacement + " node placement");
	Graph g = new Graph(N);
	super.PlaceNodes(g,ModelConstants.RT_NODE);   	/* Step1:  Place Nodes on our plane*/
	ConnectNodes(g);  	                       /* Step 2: Connect Edges following model*/

	
	AssignBW(g.getEdgesArray());           /*Step 3: assignbw*/

	return g;
    }

}










