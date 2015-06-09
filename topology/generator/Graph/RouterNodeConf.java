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

import Model.*;

/**
   Provides router specific attributes to a Node
 */
public final class RouterNodeConf extends NodeConf {
    int  rtType; 
    int asID;   //The AS that this router belongs to
    
    public RouterNodeConf() { 
	super(); 
	this.asID = -1;
	this.rtType = ModelConstants.RT_NODE;
    }

    /*constructors*/
    public RouterNodeConf(int x, int y, int z) { 
	super(); 
	this.x = x; this.y=y; this.z=z;
	this.asID=-1;
	this.rtType = ModelConstants.RT_NODE;
    }
    //this constructor used by BriteImport
    public RouterNodeConf(int x, int y, int z, int asID, int type) {
	super();
	this.x =x; this.y = y; this.z = z;
	this.asID = asID;
	this.rtType = type;
      
    }
    
  //used by GTITM-Transit Stub import
  public RouterNodeConf(int x, int y, int z, int asID) {
    super();
    this.x = x;this.y=y; this.z=z;this.asID = asID;
  }

    
    /*get methods*/
    public int  getType() { return rtType; }
    public int getCorrAS() { return asID; }
    public int getASID() { return asID; }  //alias function

    /*set methods*/
    public void setType(int t) { rtType =t; }
    public void setCorrAS(int id) { asID = id; }
    public void setASID(int id) { setCorrAS(id); } //some think this is more intuitive
    
}











