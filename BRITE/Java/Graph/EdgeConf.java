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
   EdgeConf, short for EdgeConfiguration serves as base class for
   further derivation, see ASEdgeConf, RouterEdgeConf etc.  All
   information related to the semantics of the edge (such as bandwidth, delay
   etc) should be provided in classes that extend the EdgeConf
   class.  This allows for a clear distinction between a Graph Edge
   and a Edge in your application.
*/
public class EdgeConf { 
    public double bw;  //Bandwidth
    public int edgeType; //ModelConstants.E_AS_* or E_RT_*
    
    //boolean isDirected=false;
    public EdgeConf() { };
    
    public int getEdgeType() { return this.edgeType; }
    public double getBW() { return bw; }
    
    public void setEdgeType(int t) { this.edgeType =t ; }
    public void setBW(double d) { this.bw = d;}
}


