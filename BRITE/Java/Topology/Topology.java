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

package Topology;

import Graph.*;
import Model.*;
import Export.*;

import java.util.ArrayList;
import java.util.Arrays;


public final class Topology {

    Graph g;
    Model m;
    
    public Topology(Model m) {
	this.m = m;
	g = m.Generate();
    }
        
    public Topology(Graph g) { 
	this.g = g;
    }

    public void dumpToOutput() {
	System.out.println("Dumping topology:");
	System.out.println(m.toString());
	System.out.println(g);
	g.dumpToOutput();
    }

    public Model getModel() { return this.m; };
    public Graph getGraph() { return this.g; };


}





