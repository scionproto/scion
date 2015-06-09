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
 This Model implements a model proposed by Barabasi and Albert(1)
 for Autonomous Systems. Their model attempts to capture the
 emergence of power law in the frequency of outdegrees (2) in
 topologies by building a graph with Incremental Growth and
 Preferential Connectivity as driving principles.  Incremental
 Growth refers to growing networks that are formed by the continual
 addition of new nodes.  Preferential Connectivity refers to the
 tendency of a new node to connect to existing nodes that are highly
 connected.

  The probabiliy that a source node, s, is connected to a destination
  node, d, is<br>:
  
  p = (outdegree of d) / (sum of all nodes' outdegrees) <br>
 
 References to the Papers: <br>
 
 (1) Albert-Laszlo Barabasi and Rega Albert.  Emergence of Scaling in
Random Networks. Science, pages 509-512, October 1999.  <br>
 
(2) Michalis Faloutsos, Pedro Faloutsos, and Christos Faloutsos. On
Power-Law Relationships of the Internet Topology.  In ACM Computer
Communication Review, Cambridge, MA, September 1999.

 */
public class ASBarabasiAlbert extends ASModel {
    
    /**      * 
     * @param N The Number of Nodes that the topology will have
     * @param HS Length of outer plane
     * @param LS Length of inner square
     * @param nodePlacement The type of node placement use  as defined in  
     *     ModelConstants
     * @param m The number of new nodes that a new node must connect with
     * @param bwDist the bandwidth distribution on the edge used
     * @param bwMin the minimum bw
     * @param bwMax the max bw an edge can have
     */
    public ASBarabasiAlbert(int N, int HS, int LS,  
			    int nodePlacement, int m, int bwDist,
			    double bwMin, double bwMax){
	this.N = N;
	this.HS = HS; this.LS = LS;
	this.nodePlacement = nodePlacement;
	this.m = m;	
	this.bwDist = bwDist;
	this.bwMin = bwMin;
	this.bwMax = bwMax;
    
	
    }
    
  /** Constructs a string representation of this model and the
   * parameters used.  Useful when exporting the generated topology
   * to a file.
   * 
   * @return A string representation of this model
   */
  public String toString() { 
    String modelParams = "Model ("+ModelConstants.AS_BARABASI+" - ASBarabasi):  ";
    modelParams += N+" " + HS + " " + LS + " "+ nodePlacement + "  " + m + "  ";
    modelParams +=  bwDist + " "+bwMin+ " " + bwMax + " \n";
    return modelParams;
  }
  
  
  /**Connects Nodes of a disconnected graph.  The probabiliy
     that a source node, s, is connected to a destination node,
     d, is<br>:
     
     p = (outdegree of d) / (sum of all nodes' outdegrees) <br>
     
     @param g a disconnected graph
  */
  public void ConnectNodes(Graph g) {
    int N = g.getNumNodes();
    int sumOutDeg=0;
    Node[] nodesV = g.getNodesArray();
    int[] nodesOutDeg = new int[N];
    
    
    /*initialize nodesOutDeg array*/
    for (int k=0; k<N; ++k) {
      Node kthNode = nodesV[k];
      nodesOutDeg[k]=kthNode.getOutDegree();
    }
    
    /*make a fully connected clique*/
    for (int i=0; i<=m; ++i) {
      for (int j=i+1; j<=m; ++j) {
	Node src = nodesV[i]; 
	Node dst = nodesV[j]; 
	/*create new edge*/
	Edge e = new Edge(src, dst);
	e.setEdgeConf(new ASEdgeConf());
	g.addEdge(e);
	nodesOutDeg[i] = src.getOutDegree();
	nodesOutDeg[j] = dst.getOutDegree();
	sumOutDeg+=2;
      }
    }
    for (int i=m+1; i<N; ++i) {
      Node src = nodesV[i];
      int numEdgesAdded =0;
      
      while (numEdgesAdded < m) {
	/*compute cumulative degree vectors so that tossing coins is easier*/
	double cumuValue = 0;
	
	/*flip a coin*/
	double d = Distribution.getUniformRandom(ConnectRandom);
	
	/*determine "slot" where coin fell, that is our dest node */
	double last = 0;
	int dstI=0;
	for (dstI=0; dstI<nodesOutDeg.length; ++dstI){
	  last+=(double) nodesOutDeg[dstI]/sumOutDeg;  //this is how edge probability is computed
	  if (d<last)
	    break;
	}
	//	System.out.println(dstI+" " + nodesV.length+" " + d);
	if (dstI==nodesV.length) dstI--;
	Node dst = nodesV[dstI]; 
	/*no self loops; no multiedges*/
	if (i == dstI) continue;
	if (g.hasEdge(src, dst)) continue;
	
	/*create & add edge to graph*/
	Edge e = new Edge(src, dst);
	e.setEdgeConf(new ASEdgeConf());
	g.addEdge(e);
	/*update our nodesOutDeg array*/
	nodesOutDeg[dstI]++;
	++sumOutDeg;
	++numEdgesAdded;
	
      } //finished adding m edges
      sumOutDeg+=m;
      nodesOutDeg[i]+=m;
      
    } //finished adding m edges for all nodes
    
    
  }
  
  /** 
   * Generating a graph according to the Barabasi-Albert model is a three step process that involves:
   * <br>
   * 1) placing the nodes on the plane (parent class, ASModel handles this entirely)
   * 2) interconnecting the nodes according to their outdegrees. 
   * 3) assigning a bandwidth (but the Barabasi-Albert model doesn't say anything about this.)
   *
   * @return The graph generated by this model
   */
  public Graph Generate() {
    //System.out.println("Generating " + N + " node graph with " + nodePlacement + " node placement");
    
    Graph g = new Graph(N);
    
    super.PlaceNodes(g, ModelConstants.AS_NODE);
    
    /*Connect Edges following Barabasi*/
    Util.MSGN("Connecting Nodes...");
    ConnectNodes(g);
    System.out.println("\t DONE.");
    
    /*Assign BW*/
    AssignBW(g.getEdgesArray());           /*Step 3: assignbw*/
    return g;
  }
  
}



