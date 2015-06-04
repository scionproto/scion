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
import java.util.Random;


/** 
 This Model implements a model proposed by Waxman(1).  RouterWaxman is
 the router level analog of the same model.  Waxman's model produces
 random graphs based on the Erdos-Renyi random graph model on two
 dimensional planes.  The interconnection of two nodes in the Waxman
 model is based on the distance that seperates them in the HSxHS
 plane.  The probability function used by the Waxman model to compute
 that there exists an edge between two nodes u, v is: <p>

<center> P(u,v) = alpha * e ^ (-d / (beta*L)) </center> <p> 

where alpha and beta are Waxman parameters, d is the euclidean
distance (in the plane) between nodes u and v and L is the maximum
distance between any two nodes in the plane. <p>

<br>
 References: <br>
(1) B. Waxman. Routing of Multipoint Connections.  IEEE
J. Select. Areas Commun., December 1988.  */

public final class ASWaxman extends ASModel {
   
   double alpha, beta;   
    public ASWaxman(int N,int HS, int LS, int nodePlacement, int m, 
		    double alpha, double beta, int growthType, int bwDist,
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
	String modelParams = "Model ("+ModelConstants.AS_WAXMAN+" - ASWaxman):  ";
	modelParams += N+" " + HS + " " + LS + " " +nodePlacement + "  " + m + "  ";
	modelParams += alpha + " " + beta + " " + growthType + " " + bwDist + " ";
	modelParams += bwMin+ " " + bwMax + " \n";
	return modelParams;
     
    }


    /** Computes the probability that an edge will exist between src and dst nodes.
	The exact probability between two nodes u and v, according to the Waxman model is given by:
	
	P(u,v) = alpha * e ^ (-d / (beta*L)) <br> 
	
	where alpha and beta are Waxman parameters, d is the euclidean
	distance (in the plane) between nodes u and v and L is the maximum
	distance between any two nodes in the plane. 
    */
    private double getEdgeProb(Node src, Node dst) {
	if (src==null) System.out.println("src is null");
	int x1 =   (src.getNodeConf()).getX();
	int y1 =   (src.getNodeConf()).getY();
	int  x2 =   (dst.getNodeConf()).getX();
	int  y2 =   (dst.getNodeConf()).getY();
	int  diffX = x1 -x2;
	int diffY = y1-y2;
	double d =  Math.sqrt(diffX*diffX + diffY*diffY);
	double L = Math.sqrt(2.0) * HS;
	return (double) (alpha *  Math.exp(-1.0 * (d/(beta*L))));
    }
    
    
    public void ConnectNodes(Graph g) {
	
	Util.MSG("Connecting Nodes...");
	
	
	int N = g.getNumNodes();
	Node[] nodesV = g.getNodesArray();

	if (growthType == ModelConstants.GT_ALL) {
	    int numNodesConnected = 0;
	    while (numNodesConnected < N) {
		int rand1 = (int)  (Distribution.getUniformRandom(ConnectRandom) * N);
		Node src = nodesV[rand1]; //g.getKthNode(rand1);
		int numEdgesAdded = 0;
		while (numEdgesAdded < m || numNodesConnected<N) {
		    /*pick dst node randomly*/
		    int rand2 = (int)  (Distribution.getUniformRandom(ConnectRandom) * N);
		    Node dst = nodesV[rand2];
		    if (rand1 == rand2) continue;        //no self loops
		    if (g.hasEdge(src, dst)) continue; //no multiedges
		    
		    double p = getEdgeProb(src, dst);
		    if (Distribution.getUniformRandom(ConnectRandom) < p)
			{
			    Edge e = new Edge(src, dst);
			    e.setEdgeConf(new ASEdgeConf());
			    g.addEdge(e);
			    if (src.getOutDegree() == 1) 
				++numNodesConnected;
			    if (dst.getOutDegree() == 1)
				++numNodesConnected;
			    ++numEdgesAdded;
			}
		}		    
	    }
	    // Util.DEBUG("numConnectedNodes = " + numNodesConnected);
	} /*end GT_ALL*/

	else if (growthType == ModelConstants.GT_INCREMENTAL) {
	    for (int i = m; i<N; ++i) {
		Node src = nodesV[i];
		int numEdgesAdded=0;
		while (numEdgesAdded < m) {
		    if (src.getOutDegree()>= (N-m)) break;
		    int rand = (int)  (Distribution.getUniformRandom(ConnectRandom) * i);
		    Node dst = nodesV[rand];
		    if (i==rand) continue;
		    if (g.hasEdge(src,dst)) continue;
		    double p = getEdgeProb(src, dst);
		    if (Distribution.getUniformRandom(ConnectRandom) < p) {
			Edge e = new Edge(src, dst);
			e.setEdgeConf(new ASEdgeConf());
			g.addEdge(e);
			++numEdgesAdded;
		    }
		}
	    }
	    for (int i=0; i<m; ++i) {
		Node src = nodesV[i]; 
		int numEdgesAdded =0;
		while (numEdgesAdded  < m) {
		    if (src.getOutDegree()>= (N-m)) break;

		    int rand = (int) (Distribution.getUniformRandom(ConnectRandom)*(N-m)); /*pick rand b/w m..N*/
		    Node dst = nodesV[rand];
		    if (dst==null) {
			Util.ERR("Nullpointer exception, dst= null:"+ "  rand = " +rand+ " and g's numnodes = "  + g.getNumNodes());
		    }
		    if (i==rand) continue; //this should never happen
		    if (g.hasEdge(src,dst)) continue;
		    
		    double p = getEdgeProb(src, dst);
		    if (Distribution.getUniformRandom(ConnectRandom) < p) {
			Edge e = new Edge(src, dst);
			e.setEdgeConf(new ASEdgeConf());
			g.addEdge(e);
			++numEdgesAdded; 
		    }
		}
	    }
	}	 /*end GT_INCREMENTAL*/
	else { 
	    System.out.println("[BRITE ERROR]:  Growth Type not found.");
	    System.exit(0);
	}
    }

    public Graph Generate() {
      //	Util.MSG("Generating " + N + " node graph with " + nodePlacement + " node placement");
	Graph g = new Graph(N);
	super.PlaceNodes(g,ModelConstants.AS_NODE);   	/* Step1:  Place Nodes on our plane*/
	ConnectNodes(g);  	/* Step 2: Connect Edges following model*/

	AssignBW(g.getEdgesArray());

	return g;
    }

}







