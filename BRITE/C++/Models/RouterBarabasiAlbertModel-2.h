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
/*  Author:    Alberto Medina                                               */
/*             Anukool Lakhina                                              */
/*  Title:     BRITE: Boston university Representative Topology gEnerator   */
/*  Revision:  2.0         4/02/2001                                        */
/****************************************************************************/
#ifndef RT_BAR_2_MODEL_H
#define RT_BAR_2_MODEL_H
#pragma interface

#include "RouterBarabasiAlbertModel.h"

////////////////////////////////////////////////
//
// class RouterBarabasiAlbert2
// Derived class for RouterBarabasiAlbert model. 
// This model is the new version of the model 
// implemented by RouterBarabasi-1.
// It implies Incremental growth and preferential
// connectivity.
// It Builds router-level topologies 
//
////////////////////////////////////////////////

class RouterBarabasiAlbert_2_Par;

class RouterBarabasiAlbert_2 : public RouterBarabasiAlbert {

 public:
  
  RouterBarabasiAlbert_2(RouterBarabasiAlbert_2_Par* par);
  string ToString();

 private:

  /*virtual*/ void InterconnectNodes(Graph *g);
  int SumDj;  // Sum of outdegrees of all nodes
  double P;
  double Q;

};

#endif /* RT_BAR_2_MODEL_H */


