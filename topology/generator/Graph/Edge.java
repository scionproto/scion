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

package Graph;

import java.lang.*;
import java.util.Comparator;



/**
   The Edge class for our Graph contains only the base minimum member
   variables.  Environment specific semantics (such as RouterEdge or
   bandwidth etc) that are often attached to an edge are divorced from
   the this class and stored in a decorator class, EdgeConf (short for
   EdgeConfiguration).  As such you can add/remove attributes to the Edge at
   run-time without having to change the Edge representation.  <p> We
   use the decorator pattern as the relationship between a Edge and
   its configuration, EdgeConf.  This pattern is described in Design Patterns:
   Elements of Reusable Object-Oriented Software by Gamma et al.
   ISBN#: 0-201-63361-2.  <p>
   
   Like NodeIDs, unique edge ids are determined by using a static int
   and incrementing it each time a new edge is created.  This is the
   default method.  However, for improved lookup performance, we also
   provide alternative methods of computing EdgeIDs which embed the
   ids of the source and destination nodes of this edge in the EdgeID.
   As such given the source and destination node, one can compute the
   EdgeID in constant time. See Edge.computeID(..) and
   Edge.computeDirectedID(..) methods for more on how this is done.  <p>

   NOTE: The direction of the edge can be either DIRECTED or UNDIRECTED.
   This allows for graphs that contain a hybrid of directed and
   undirected edges.

*/

public final class Edge {
  Node src;
  int direction;
  Node dst;
  int id;
  int color;    
  double BW;
  double dist=-1;
  EdgeConf e;
  double delay = -1;
  static double SPEEDOFLIGHT = 299792458.0;
  
  static int edgeCount=-1;
  public static EdgeIDComparator IDcomparator = new EdgeIDComparator();
  public static EdgeSrcIDComparator SrcIDComparator = new EdgeSrcIDComparator();
  
    /** Class Constructor.  
	@param src The source node of this edge
	@param dst The destination node of this edge
     */
    public Edge(Node src, Node dst) {
	this.src = src; 
	this.dst = dst;
	this.e = new EdgeConf();
	this.id = ++edgeCount;
	this.direction = GraphConstants.UNDIRECTED;  //by default we select this
    }
    
    
    /**
       Set the direction of this edge to either GraphConstants.DIRECTED or GraphConstants.UNDIRECTED
       @param d the direction of the graph, one of the possible values specified in class GraphConstants
    */
    public void setDirection(int d) {
	direction = d;
    }
    
    /**
       returns direction of this edge. (either GraphConstants.DIRECTED or GraphConstants.UNDIRECTED)
       
       @return int The Direction of the edge.  Either GraphConstants.DIRECTED or GraphConstants.UNDIRECTED
     */
    public int getDirection() {
	return direction;
    }

  
    /** Computes a unique EdgeID These IDs have the property that
	id(src,dest) = id(dest,src) and so should be used with undirected
	graphs only.  See the computeDirectedID method for computing
	edgeIDs for directed graphs. 
	
	An EdgeID embeds the IDs of the srouce and destination nodes
	of this edge in it.  This is done by simply concatenating the
	bit represenation of the source and destination.  If the
	concatenated represenation is larger than an int, -1 is
	returned.  The caller of the function should check for this
	condition and if a -1 is returned, computeLongID should be
	called instead.

	 @param srcID  generally, the id of the source-node
	 @param dstID  generally, the id of the dest-node 
	 @return int returns an int which is srcID concattenated with
	 dstID. -1 if concattenated result overflows int.
	 
    */
  public static int computeID(int srcID, int dstID) {
	//WARNING: only works for undirected  (a,b) has same id as (b,a)
	
      int d = dstID >>16;
      int s = srcID >>16;
      if (d==0 && s==0) {
	  if (srcID < dstID)
	      return ((srcID<<16)|dstID);   //this gurantees (s,d) to have sameid as (d,s)
	  else return ((dstID<<16)|srcID);    
	}
	//System.out.println("DEBUG:  need long edgeid for "+srcID + " and " + dstID);
	return -1;

    }

    /**
       Similar to computeID(src,dest) except returns a long id.  this
       should be used if the srcID and destID are too large to yield
       an EdgeID which can fit in an int.  Gurantees that id(src,dst)
       == id(dst,src)
       
       @param srcID  the node-id of the srouce node
       @param dstID  the node-id of the dest node
       @return long  this edgeID is a long repr. of srcID concattenated with dstID

    */
   public static long computeLongID(int srcID, int dstID) {
	long lo;
	if (srcID<dstID) {
	  lo =((long) srcID<<32|dstID);
	}
	else {
	  lo = ((long) dstID<<32|srcID);
	}
	//System.out.println("** lo="+lo);
	return lo;
	
    }
  

  /*Analagous to computeID() above but this computes IDs for directed graph. 
    That is, it  computeDirectedID(a,b) != computeDirectedID(b,a)
    
    @param srcID  the source node id
    @param dstID  the desitnation node id
    @return int  the result of concatenating srcID with dstID, or -1 if the result overflows an int. 
 
  */
  public static int computeDirectedID(int srcID, int dstID) {
    int d = dstID >>16;
    int s = srcID >>16;
    
    if (d==0 && s==0) 
      return ((srcID<<16)|dstID); 
    return -1;

    }

    /**
       Analagous to computeLongID above but computes ID for directed graph.  That is, ids returned by
       this method gurantee that id(a,b) ! = id(b,a).
       
       @param srcID the source node id
       @param dstID the dest node id
       @return long  the result of concatenating srcID with dstID
     */
    public static long computeDirectedLongID(int srcID, int dstID) {
	long lo =((long) srcID<<32|dstID);
	return lo;
    }
  
    
    /** compute the euclidean distance for this edge.  uses the (x,y) coords of the source and
	destination nodes to do this.
	
	@return double  the eculidean dist:  d = sqrt( (x1-x2)^2 + (y1-y2)^2).
    */
  public double getEuclideanDist() {
    if (dist>0) return dist; //already computed
    int x1 = src.getNodeConf().getX();
      int y1 = src.getNodeConf().getY();
      
      int x2  =dst.getNodeConf().getX();
      int y2 = dst.getNodeConf().getY();
      
      int diffX = x1-x2;
      int diffY = y1-y2;
      
      dist = Math.sqrt( diffX*diffX + diffY*diffY);
      return dist;
  }

  public double getDelay() {
    if (dist==-1) dist = getEuclideanDist();
    
    delay =  (1000.0*1000.0* (double)dist)/SPEEDOFLIGHT;
    return delay;
  }

    /*get methods*/
    public Node getSrc() { return src; }
    public Node getDst() { return dst; }
    public int getID() { return this.id; }
    public static int getEdgeCount() { return edgeCount; }
    public int getColor() { return color; }
    public EdgeConf getEdgeConf() { return e; }
    public double getBW() { return this.BW; };

    /*set methods*/
    public void setSrc(Node src) { this.src=src; }
    public void setDst(Node dst) { this.dst = dst; }
    public void setColor(int c) { color=c;}
    public void setEdgeConf(EdgeConf e) { this.e = e; }
    public void setBW(double bw) { this.BW = bw; }
    public void setEuclideanDist(double d) { this.dist = d;}
   

}
/** EdgeID comparator provides a comparator to compare Edge IDs.  You
 can follow this template and trivially write your own comparator if
 you need for instance, to sort the edges in another fashion, eg
 source node-ids.  We use this comparator to sort edges when printing them
 to a file.*/
class EdgeIDComparator implements Comparator {

  public int compare(Object e1, Object e2) {
    int e1id = ((Edge)e1).getID();
    int e2id = ((Edge)e2).getID();
    
    /*if e1 < e2 then return -1*/
    if (e1id < e2id) return -1;
    /*if e1==e2, then return 0*/
    if (e1id == e2id) return 0;
    /*if e1> e2 then return 1*/
    if (e1id > e2id ) return 1;

    /*should never get here*/
    return 1;
    
  }
  
}

/** EdgeSrcID comparator provides a comparator to compare by Edge src IDs.  
 */
class EdgeSrcIDComparator implements Comparator {

  public int compare(Object e1, Object e2) {
    int e1id = ((Node)((Edge)e1).getSrc()).getID();
    int e2id = ((Node)((Edge)e2).getSrc()).getID();
    
    /*if e1 < e2 then return -1*/
    if (e1id < e2id) return -1;
    /*if e1==e2, then return 0*/
    if (e1id == e2id) return 0;
    /*if e1> e2 then return 1*/
    if (e1id > e2id ) return 1;

    /*should never get here*/
    return 1;
    
  }
}



