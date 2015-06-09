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



/**
   NodeConf, short for NodeConfiguration serves as base class for
   further derivation, see ASNodeConf, RouterNodeConf etc.  All
   information related to the semantics of the node (such as (x,y)
   coords etc) should be provided in classes that extend the NodeConf
   class.  This allows for a clear distinction between a Graph node
   and a Node in your application.
*/
public class NodeConf {
    
    double cost=0;
    int x, y, z;
    int nodeType;  //ModelConstants.AS_NODE, ModelConstants.RT_NODE

    
    /** Constructor 1:  default constructor that intializes all NodeConf fields to default values*/
    public NodeConf() {    }

    /** Constructor 2:  specifies the node "cost" */
    public NodeConf(double c) { cost=c;}
    
    /** Constructor 3:  specifies the x,y,z coords of the node*/
    public NodeConf(int x, int y, int z) {
	this.x = x; this.y=y; this.z = z;
    }
    
    /*get methods*/
    public double getCost() { return cost; }
    public int getX() { return x; }
    public int getY() { return y; }
    public int getZ() { return z; }
    public int getNodeType() { return this.nodeType; }
    
    /*set methods*/
    public void setCost(double c) { cost=c;}
    public void setCoordinates(int x,int y, int z) { this.x = x; this.y=y; this.z=z; }
    public void setNodeType(int t) { this.nodeType = t;}

}




