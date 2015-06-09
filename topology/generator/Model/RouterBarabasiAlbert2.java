package Model;

import Graph.*;
import Util.*;

import java.lang.*;
import java.util.*;
import java.io.*;    

/**
   This model implements an extension of the BarabasiAlbert model,
   proposed in [1].  This model differs from version 1 of the
   BarabasiAlbert model in that it "offers a more realistic description
   of network formation by incorporating additional local events that are
   known to appear in real networks." [2].  Specifically, this model
   allows for rewiring of links.  Actual details of this model can be
   found in [2]. <br>
   
   Note: This model may return graphs that are disconnected.  It is
   advisable to extracted the largest connected component.  Usually
   this component contains 75%-85% of the original graph.
   
   <font size=-1>
   References: <br>
   [1] Albert-Laszlo Barabasi and Rega Albert.  Emergence of Scaling in
   Random Networks. Science, pages 509-512, October 1999.  <br> <br> 
   [2] Reka Albert and Albert-Laszlo Barabasi.  Topology of evolving
   networks: local events and universality. 
   

   
*/


public  class RouterBarabasiAlbert2 extends RouterBarabasiAlbert {
    
  double p;
  double q;
  
  public RouterBarabasiAlbert2(int N, int HS, int LS,  int nodePlacement, int m, int bwDist,
			       double bwMin, double bwMax, double p, double q)    {
    super(N, HS, LS, nodePlacement, m, bwDist, bwMin, bwMax);
    this.p = p;
    this.q = q;
  }
  
  
    public String toString() { 
	String modelParams = "Model ("+ModelConstants.RT_BARABASI2 +" - RTBarabasiAlbert2):  ";
	modelParams += N+" " + HS + " " + LS + " " + nodePlacement + "  " + m + "  ";
	modelParams +=  bwDist + " "+bwMin+ " " + bwMax + " " + p +" " + q+ " \n";
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
	
	/*make a fully connected clique*/
	for (int i=0; i<=m; ++i) {
	  for (int j=i+1; j<=m;  ++j) {
	    Node src = nodesV[i]; 
	    Node dst = nodesV[j]; 
	    //create new edge
	    Edge e = new Edge(src, dst);
	    e.setEdgeConf(new RouterEdgeConf());
	    g.addEdge(e);
	    nodesOutDeg[i] = src.getOutDegree();
	    nodesOutDeg[j] = dst.getOutDegree();
	    sumOutDeg+=2;
	  }
	}
	
	
	int numNodesAdded=m;
	//g.dumpToOutput();
	while (numNodesAdded < N) {
	  /*decide if we are going to add more links, rewire or add new node */
	  double coinFlip = Distribution.getUniformRandom(ConnectRandom); 
	  
	  //if graph is at or near-clique,  don't rewire or add (we can't anwyay), just add nodes*/
	  int maxEdges = (numNodesAdded*(numNodesAdded-1) / 2)-(m+1);
	  if (g.getNumEdges() >= maxEdges) {
	    coinFlip=p+q+(double)0.001;  //this will trigger an add node
	  }
	   
	  
	  if (coinFlip <= p) {  /*add m links*/
	      //	    Util.DEBUG(numNodesAdded+": adding m links - p="+p+"  coinFlip="+coinFlip);
	    int numEdgesAdded = 0;
	    while (numEdgesAdded < m) {
	      if (numNodesAdded == m ) { 
		//Util.DEBUG("** breakign out of adding links b/c numNodesAdded==m");
		break ;
	      }
	      // int srcIndex = Distribution.getUniformRandom(ConnectRandom, 0, numNodesAdded);
	      double d = Distribution.getUniformRandom(ConnectRandom);
	      double last=0;
	      int srcIndex = 0;
	      for (srcIndex=0; srcIndex<numNodesAdded; ++srcIndex) {
		last+=(double) nodesOutDeg[srcIndex]/sumOutDeg;
		if (d<last) break;
	      }


	      d = Distribution.getUniformRandom(ConnectRandom);
	      last=0;
	      int dstIndex = 0;
	      for (dstIndex=0; dstIndex<numNodesAdded; ++dstIndex) {
		last+=(double) nodesOutDeg[dstIndex]/sumOutDeg;
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
	    }
	  
	  }
	  
	  else if ( (coinFlip > p) && (coinFlip < (p+q)) ) { 	    /*rewire m links*/
	      //	   Util.DEBUG(numNodesAdded+": rewiring m links - q="+q+"  coinFlip="+coinFlip);
	   int numEdgesRewired=0;
	   while (numEdgesRewired<m) {
	     
	     int randSrcIndex = Distribution.getUniformRandom(ConnectRandom, 0, numNodesAdded);//nodesV.length);
	     Node randSrc = nodesV[randSrcIndex];
	     Node[] neighbors = g.getNeighborsOf(randSrc);
	     if (neighbors.length<1 )
	       break;
	     int randDstIndex=0;
	     Node randDst = neighbors[0];
	      if (neighbors.length==1) {
		randDstIndex=0;
		randDst=neighbors[0];
	      }
	      else {
		randDstIndex = Distribution.getUniformRandom(ConnectRandom, 0, neighbors.length);
		randDst = neighbors[randDstIndex];
	      }
	      double d = Distribution.getUniformRandom(ConnectRandom);
	      double last=0;
	      int dstIndex=0;
	      for (dstIndex=0; dstIndex<numNodesAdded; ++dstIndex) {
		last+=(double) nodesOutDeg[dstIndex]/sumOutDeg;
		if (d<last) break;
	      }
	      if (dstIndex==randSrcIndex) 
		continue;
		
	      if (g.hasEdge(randSrcIndex, dstIndex)) 
		continue;
	
	      g.removeEdge(randSrc, randDst);
	      nodesOutDeg[randDstIndex]--;
	      //nodesOutDeg[randSrcIndex]--;
	      //sumOutDeg -= 2;
	      
	      Node dst = nodesV[dstIndex];
	      Edge e = new Edge(randSrc, dst);
	      e.setEdgeConf(new ASEdgeConf());
	      g.addEdge(e);
	      // nodesOutDeg[randSrcIndex] ++; 
	      nodesOutDeg[dstIndex] ++;
	      //sumOutDeg+=2;
	      ++numEdgesRewired;
	     
	    }
	    

	  }

	  
	  else { 	    /*add new node with m neighbors*/
	      //	    Util.DEBUG(numNodesAdded+": adding a new node!");
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
		last+=(double) nodesOutDeg[dstI]/sumOutDeg;
		if (d<last)
		  break;
	      }
	      if (dstI== nodesV.length) dstI--;
	      Node dst = nodesV[dstI]; 
	      /*no self loops; no multiedges*/
	      if (src == dst) { 
		//System.out.println(numNodesAdded+" SRC==DST stuck? ("+src+", "+dst+")  d="+d); 
		//System.out.print("sumOutDeg="+sumOutDeg+"  outDegArray---> ");
		//for (int k=0; k<=numNodesAdded; ++k) {
		//  System.out.print(nodesOutDeg[k]+", ");
		//} 
		//System.out.println();
		//g.dumpToOutput(); 
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
	      e.setEdgeConf(new RouterEdgeConf());
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
	  }
	}
    }

  public Graph Generate() {
    Graph g = new Graph(N);
    super.PlaceNodes(g, ModelConstants.RT_NODE);
    //Util.MSG("Connecting Noes...");
    ConnectNodes(g);
    
    super.AssignBW(g.getEdgesArray());
    return g;
    
  }


    /*  public static void main(String args[]) {
      RouterBarabasiAlbert2 rb = new      RouterBarabasiAlbert2(9200, 1000, 1000, 1, 2, 1, (double)10.0,
							      (double)10.0, (double)0.0, (double)0.0);
      Graph g = rb.Generate();
      
      double cc = Analysis.Metrics.CC.computeCC(g, g.getNodesArray(), g.getEdgesArray());
      System.out.println("cc="+cc);
      Main.Briana b = new Main.Briana(g);
      b.doFFF99();
      }*/
      
      /*    String fname = args[0];
    BufferedWriter bw= null;
    
    try {
      bw = new BufferedWriter(new FileWriter(new File(fname)));
    }
    catch (Exception e) {}
    for (double p=0.2; p<1; p+=0.1) {
      if (p>0.91) break;
      System.out.print(p+": ");
      for (double q=0; (p+q)<0.9; q+=0.1) {
	if ((p+q)>0.91) break;
	try {
	  if (cc>0.1) {
	    bw.write("*** "+cc+" " + p+" " + q);
	    bw.newLine();
	    bw.flush();
	  }
	  else {
	    bw.write(cc+" " + p+" " + q);
	    bw.newLine();
	    bw.flush();
	  }
	}
	catch (IOException e) {
	  Util.ERR("oops.", e);
	}
	System.out.println("DONE!");
      }
      System.out.println("DONE WITH 10!");
    }
   try { bw.close();
   }
   catch (IOException e2) {};
  }
      */
    
  
    
}




