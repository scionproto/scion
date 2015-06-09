package Model;

import Graph.*;
import Topology.*;
import Export.*;
import Util.*;

import java.lang.*;
import java.util.*;
import java.io.*;    

/**
   This model implements the Generalized Linear Preference (GLP) Model
    proposed in [1].  Very similar to Barabasi-Albert2 model except
    the GLP model introduces a tuning parameter for Preferential
    Connectivity, beta.  Beta can be tuned to capture the intuition
    that a node may connect to another more preferentially than
    others.  By tuning beta, Bu-Towsley show that small-world
    properties that have been measured in real Internet maps can be
    also be reproduced in generators.  Details can be found in [1]. 
     <br>
   <font size=-1> 
   References <br>
   [1] T. Bu and D. Towsley.  On Distinguishing between Power-Law Internet
   Topology Generators.  In Proceedings of IEEE Infocom 2002.
    
*/


public final class ASGLP extends ASBarabasiAlbert {
    
  double p;
  double beta;
  
  public ASGLP(int N, int HS, int LS,  int nodePlacement, int m, int bwDist,
			       double bwMin, double bwMax, double p, double beta)    {
    super(N, HS, LS, nodePlacement, m, bwDist, bwMin, bwMax);
    this.p = p;
    this.beta = beta;
  }
  
  
    public String toString() { 
	String modelParams = "Model ("+ModelConstants.AS_GLP +" - ASGLP):  ";
	modelParams += N+" " + HS + " " + LS + " " + nodePlacement + "  " + m + "  ";
	modelParams +=  bwDist + " "+bwMin+ " " + bwMax + " " + p +" " + beta+ " \n";
	return modelParams;
    }
    
    

    public void ConnectNodes(Graph g) {
	int N = g.getNumNodes();
	int sumOutDeg=0;
	Node[] nodesV = g.getNodesArray();
	Arrays.sort(nodesV, Node.IDcomparator); 
	int[] nodesOutDeg = new int[N];
	Edge[] edges = g.getEdgesArray();
	
	/*initialize nodesOutDeg array*/
	for (int k=0; k<N; ++k) {
	  Node kthNode = nodesV[k];
	  nodesOutDeg[k]=kthNode.getOutDegree();
	}
	
	/*start with m nodes connected thru m-1 edges*/
	for (int i=1; i<=m; ++i) {
	  
	    Node src = nodesV[i-1]; 
	    Node dst = nodesV[i]; 
	    //create new edge
	    Edge e = new Edge(src, dst);
	    e.setEdgeConf(new ASEdgeConf());
	    g.addEdge(e);
	    nodesOutDeg[i-1] = src.getOutDegree();
	    nodesOutDeg[i] = dst.getOutDegree();
	    sumOutDeg+=2;
	  
	}
	
	
	int numNodesAdded=m;
	//g.dumpToOutput();
	while (numNodesAdded < N) {
	  /*decide if we are going to add more links, or add new node */
	  double coinFlip = Distribution.getUniformRandom(ConnectRandom); 
	  
	  //if graph is at or near-clique,  don't  add links (we can't anwyay), just add nodes*/
	  int maxEdges = (numNodesAdded*(numNodesAdded-1) / 2)-(m);
	  if (g.getNumEdges() >= maxEdges) {
	    coinFlip=p+(double)0.001;  //this will trigger an add node
	  }
	   
	  
	  if (coinFlip <= p) {  /*add m links*/
	    ////Util.DEBUG(numNodesAdded+": adding m links - p="+p+"  coinFlip="+coinFlip);
	    int numEdgesAdded = 0;
	    while (numEdgesAdded < m) {
	      if (numNodesAdded == m ) { 
		//////Util.DEBUG("** breakign out of adding links b/c numNodesAdded==m");
		break ;
	      }
	     
	      double d = Distribution.getUniformRandom(ConnectRandom);
	      double last=0;
	      int srcIndex = 0;
	      for (srcIndex=0; srcIndex<numNodesAdded; ++srcIndex) {
		last+=(double) (nodesOutDeg[srcIndex]-beta)/(sumOutDeg-numNodesAdded*beta);
		if (d<last) break;
	      }
	      
	      d = Distribution.getUniformRandom(ConnectRandom);
	      last=0;
	      int dstIndex = 0;
	      for (dstIndex=0; dstIndex<numNodesAdded; ++dstIndex) {
		last+=(double) (nodesOutDeg[dstIndex]-beta)/(sumOutDeg-numNodesAdded*beta);
		if (d<last) break;
	      }
	     
	      if (dstIndex == srcIndex) continue;
	      if (g.hasEdge(srcIndex, dstIndex)) continue;
	      if (g.hasEdge(dstIndex, srcIndex)) continue; 
	     
	      
	      Node src = nodesV[srcIndex];
	      Node dst = nodesV[dstIndex];
	      
	      /*create & add edge to graph*/
	      Edge e = new Edge(src, dst);
	      e.setEdgeConf(new ASEdgeConf());
	      g.addEdge(e);
	      /*update our nodesOutDeg array*/
	    
	      nodesOutDeg[dstIndex] ++;
	      nodesOutDeg[srcIndex] ++;
	      sumOutDeg+=2 ;
	      ++numEdgesAdded;
	      
	      if (numEdgesAdded%100==0) System.out.print(numEdgesAdded+" " );
	    }
	  
	  }
	  
	  
	  
	  else { 	    /*add new node with m neighbors*/
	    ////Util.DEBUG(numNodesAdded+": adding a new node!");
	    ++numNodesAdded;
	    if (numNodesAdded == nodesV.length) break;
	    Node src = nodesV[numNodesAdded];
	    int numEdgesAdded =0;
	    while (numEdgesAdded < m) {
	      /*compute cumulative degree vectors so that tossing coins is easier*/
	      double cumuValue = 0;
	      /*flip a coin*/
	      double d = Distribution.getUniformRandom(ConnectRandom);
	      /*determine "slot" where coin fell, that is our dest node */
	      double last = 0;
	      int dstI=0;
	      //for (dstI=0; dstI<nodesOutDeg.length; ++dstI){
	      for (dstI=0; dstI<numNodesAdded; ++dstI) {
		last+=(double) (nodesOutDeg[dstI]-beta)/(sumOutDeg-numNodesAdded*beta);
		if (d<last)
		  break;
	      }
	      if (dstI== nodesV.length) dstI--;
	      Node dst = nodesV[dstI]; 
	      /*no self loops; no multiedges*/
	      if (src == dst) { 
		continue;
		
		}

	      if (g.hasEdge(src, dst)) {
		//	System.out.print("sumOutDeg="+sumOutDeg+"  outDegArray---> ");
		//for (int k=0; k<=numNodesAdded; ++k) {
		//  System.out.print(nodesOutDeg[k]+", ");
		//} 
		//System.out.println();
		//	System.out.println(numNodesAdded+" stuck-hasEdge? ("+src+", "+dst+") d="+d);   
		//g.dumpToOutput(); 
		continue; }// continue;}
	      /*create & add edge to graph*/
	      Edge e = new Edge(src, dst);
	      e.setEdgeConf(new ASEdgeConf());
	      g.addEdge(e);
	      /*update our nodesOutDeg array*/
	      nodesOutDeg[numNodesAdded] = src.getOutDegree();
	      nodesOutDeg[dstI] = dst.getOutDegree();
	      /*increment counters*/
	      ++sumOutDeg;
	      ++numEdgesAdded;
	      
	      //finished adding m edges
	      }
	    sumOutDeg+=m;
	    nodesOutDeg[numNodesAdded]+=m;
	    //	    ++numNodesAdded;
	    //finished adding m edges for node nodes
	    	      if (numEdgesAdded%100==0) System.out.print(numEdgesAdded+" " );
	  }
	}
	
    }

  public Graph Generate() {
    Graph g = new Graph(N);
    super.PlaceNodes(g, ModelConstants.AS_NODE);
    Util.MSG("Connecting Noes...");
    ConnectNodes(g);
    
    super.AssignBW(g.getEdgesArray());
    return g;
    
  }


  public static void main(String args[]) {
  
    String outFile = args[0];
    
    ASGLP rb = new      ASGLP(100000, 1000, 1000, 1, 1, 1, (double)10.0,(double)10.0, 
				      (double)0.5294, (double)0.7124);

    Topology t = new Topology(rb);
    
    BriteExport be = new BriteExport(t, new File(outFile+".brite"));
    be.export();

    
  }
}



