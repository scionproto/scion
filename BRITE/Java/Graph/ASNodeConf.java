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

import Topology.*;
import Model.ModelConstants;


import java.util.ArrayList;

/**
   provides Autonomous System (AS) level attributes to a Node
 */
public final class ASNodeConf extends NodeConf {
    int  asType; 
    Topology t; 

    /*constructors*/
    public ASNodeConf() { 
	super(); 
	this.asType = ModelConstants.AS_NODE;
    }
    
    public ASNodeConf(int x, int y, int z) {
	super();
	this.x = x; this.y = y; this.z = z;
	this.asType = ModelConstants.AS_NODE;
    }
    
    //this constructor used by BriteImport
    public ASNodeConf(int x, int y, int z, int type) {
	super();
	this.x = x; this.y = y; this.z = z;
	this.asType = type;
    }
    
    public ASNodeConf(int asType) { 
	super(); 
	this.asType = asType;
    };

    public ASNodeConf(int asType, Topology routerT) { 
	super(); 
	this.asType = asType; 
	t=routerT; 
    }
    
    public ASNodeConf(Topology t) {
	super(); 
	this.t = t;
	this.asType = ModelConstants.AS_NODE;
    }
    
    /*toString() method*/
    //public String toString() {
    // }

    
    /*get methods*/
    public int getType() { return asType; }
    public Topology getTopology() { return t; }

    /*set methods*/
    public void setType(int t) { this.asType =t; }
    public void setTopology(Topology t, int asID) { 
	this.t = t; 
	setASIDForTopology(asID);
    }
    
    /**
     *
     *Helper function for TopDownHier Model,  basically go thru subgraph
     *(routers) of this AS node, and assign each member router this as
     *id.
     *
     */
    public void setASIDForTopology(int asID) {
	Graph g = t.getGraph();
	ArrayList nodes = g.getNodesVector();
	int size = nodes.size();
	for (int i=0; i<size; ++i) {
	    Node n = (Node) nodes.get(i);
	    if (n.getNodeConf() instanceof RouterNodeConf) {
		((RouterNodeConf)n.getNodeConf()).setCorrAS(asID);
	    }
	}

    }
    
}










