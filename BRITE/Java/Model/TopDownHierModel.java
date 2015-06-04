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
import Topology.*;
import Util.*;

import java.util.ArrayList;
import java.util.Random;

public class TopDownHierModel extends Model {

    ArrayList Models;
    int edgeConn;
    int k;  
    int bwInter;
    double interMin, interMax;
  int numASNodes;

    public TopDownHierModel(ArrayList Models, int edgeConnMethod, int k, 
			    int bwInter, double interMin, double interMax,
			    int bwIntra, double intraMin,double intraMax) 
    {
	if (Models.size()<2) {
	    System.out.println("[BRITE ERROR] Top Down Hierarchical Model requires more than one level.");
	    System.exit(0);
	}
	this.Models = Models;
	this.edgeConn = edgeConnMethod;
	this.k = k;
	this.bwInter = bwInter;
	this.interMin = interMin;
	this.interMax = interMax;

    }
    
    public String toString() { 
      String modelParams = "Model ("+ ModelConstants.HI_TOPDOWN+" - TopDown)\n";
	modelParams+= ((Model)Models.get(0)).toString() + ((Model)Models.get(1)).toString();
	return modelParams;
    }
  public int getNumASNodes() { return numASNodes; }
    
    /**
     *  Node s and Node d are nodes are AS neighbors.  Here, we connect the corresponding router level
     *  graphs of s and d according to edgeConn and update our flattened topology, gFlat.  
     *
     */  
    public void ConnectNodes(Node s, Node d, Graph gFlat, int direction) {
	
	Random r = rm.EDGE_CONN();
	Graph sG =((ASNodeConf)s.getNodeConf()).getTopology().getGraph();
	Graph dG = ((ASNodeConf)d.getNodeConf()).getTopology().getGraph();

	
	Node sFlat=null;
	Node dFlat = null; 
	
	if (edgeConn == ModelConstants.TD_RANDOM) {
	    /*pick a random node from s's subgraph*/
	    int rand = (int)  (Distribution.getUniformRandom(r)*sG.getNumNodes());
	    sFlat = sG.getKthNode(rand);
	    if (sFlat == null) System.out.println("sFlat is null");
	    /*pick a random node from g's subgraph*/
	    int rand2 = (int) (Distribution.getUniformRandom(r)*dG.getNumNodes());
	    dFlat = dG.getKthNode(rand2);
	    if (dFlat == null) {
		System.out.println("dest is null");
		System.out.println("rand2 = " + rand2 +  "   and dG's numnodes = " + dG.getNumNodes() );
		dG.dumpToOutput();
		System.exit(0);
	    }
	}
	else if (edgeConn == ModelConstants.TD_SMALLEST_NONLEAF) {
	    /*recall that a leaf is a node with degree = Model.m*/
	    int m = ((Model)Models.get(0)).getM();
	    sFlat = sG.getSmallestDegreeNodeThreshold(m);
	    dFlat = dG.getSmallestDegreeNodeThreshold(m);
	}
	else if (edgeConn == ModelConstants.TD_SMALLEST) {
	    /*get smallest degree node of sG*/
	     sFlat = sG.getSmallestDegreeNode();
	    /*get smallest degree node of dG*/
	     dFlat = dG.getSmallestDegreeNode();
	}
	else if (edgeConn == ModelConstants.TD_KDEGREE) {
	    sFlat = sG.getSmallestDegreeNodeThreshold(k);
	    dFlat = dG.getSmallestDegreeNodeThreshold(k);
	
	}
	else {
	    Util.ERR("EdgeConn Method " +edgeConn + " not found/implemented yet.");
	}
	
	if (sFlat==null || dFlat==null)
	    Util.ERR("NULL NODE found when connecting topologies in TopDownHierModel.");

	
	((RouterNodeConf)sFlat.getNodeConf()).setType(ModelConstants.RT_BORDER);
	((RouterNodeConf)dFlat.getNodeConf()).setType(ModelConstants.RT_BORDER);
	
	/*connect sFlat and dFlat in gFlat graph*/
	Edge e = new Edge(sFlat, dFlat);
	e.setEdgeConf(new ASEdgeConf());
	e.setDirection(direction);
	gFlat.addEdge(e);

	/*set bandwidth between border nodes according to bwInter and interMin, interMax*/
	AssignInterBW(e);	
    }


    private void AssignInterBW(Edge e) {
	Random BWRandom = rm.BW();

	if (bwInter == ModelConstants.BW_CONSTANT)
	    e.setBW(interMin);
	else if (bwInter == ModelConstants.BW_UNIFORM)
	    e.setBW(Distribution.getUniformRandom(BWRandom));
       	else if (bwInter == ModelConstants.BW_HEAVYTAILED)
	    e.setBW(Distribution.getParetoRandom(BWRandom, interMin, interMax, 1.2));
	else if (bwInter == ModelConstants.BW_EXPONENTIAL)
	    e.setBW(Distribution.getExponentialRandom(BWRandom, interMin)); 
       	else   e.setBW(-1);
	
    }
    
    
    public void ConnectTopologies(Graph g0, Graph gFlat) {
	//if (g0.isConnected())
	//   System.out.println("g0 is connected");
	//else System.out.println("g0 isn't connected");
	ArrayList g0Edges = g0.getEdgesVector();
	int size = g0Edges.size();
	for (int i=0; i<size; ++i) {
	    Edge e = (Edge) g0Edges.get(i);
	    ConnectNodes(e.getSrc(), e.getDst(), gFlat, e.getDirection());  /*connect the routers of neighboring AS nodes according to edgeConn method*/
	}
    } 
    
    public Graph FlattenGraph(Graph g0) {
	/*initialize ArrayList to numNodes of g0 - since this is number of graphs at bottom level*/
	ArrayList VectorOfGraphs = new ArrayList(g0.getNumNodes()); 
	ArrayList g0Nodes = g0.getNodesVector();
	int size = g0Nodes.size();
	for (int i=0; i<size; ++i) {
	    Node n = (Node) g0Nodes.get(i);
	    Graph g = ((ASNodeConf)n.getNodeConf()).getTopology().getGraph();
	    VectorOfGraphs.add(g);
	}

       Graph g= new Graph(VectorOfGraphs);
       //testing:
       return g;
    }
    
    public Graph Generate() {
	/*Step 1: Generate each level of topology*/
	Util.MSG("Generating Top Level (AS) graph)");
	Graph g0 = ((Model)Models.get(0)).Generate();  //g0 is toplevel graph (AS)
	numASNodes = g0.getNumNodes();
	
	if (g0.isConnected())
	    Util.DEBUG("AS graph is connected");
	else Util.DEBUG("AS Graph ***NOT*** connected!");
	
	Node[] vec = g0.getNodesArray();
	
	/*
	if (Models.get(1) instanceof FileModel)
	    FileGraph = ((Model)Models.get(1)).generate();
	*/  
	for (int i=0; i<vec.length; ++i) {
	    Node n = vec[i];
	    if (n.getNodeConf() instanceof ASNodeConf)
		{
		    Util.MSG("Generating Router Topology # " + (i+1)+" of"+ vec.length +"...");
		    Topology t = new Topology((Model)Models.get(1)); //level1 graphs
		    
		    /*1) set this AS node's corresponding router topology to the one generated by our
		     *level one model, and 2) for all the routers in that topology, assign them asID to 
		     *be N's id
		     */
		    ((ASNodeConf)n.getNodeConf()).setTopology(t, n.getID()); 
		    
		}
	}
	
	/*Step 2: Now flatten the graph to one level*/
	Util.MSG("Flattening Graph...");
	Graph gFlat = FlattenGraph(g0);

	
	/*Step 3: Now interconnect the disconnected portions according to edgeConn*/
	Util.MSGN("Connecting router graphs according to edgeConn method...");
	ConnectTopologies(g0, gFlat);
	System.out.println("... Done.");
		
	return gFlat;
    }



  /* 
  to debug:
  =========
  
  public static void main(String args[]) {
  
  RouterWaxman rw = new RouterWaxman(1000, 1000, 1000, 1, 2, (double)0.2, (double)0.1, 1, 1, 10, 10);
  ASWaxman aw = new ASWaxman(10, 1000, 1000, 1, 2, (double)0.2,(double) 0.1, 1, 1, 10, 10);
  ArrayList models = new ArrayList();
  models.add(aw);
  models.add(rw);
  
  TopDownHierModel td = new TopDownHierModel(models, 1, 2, 1, 10, 100, 2, 500, 700);
  td.Generate();
  
  }
  */
  
    
}






























