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
#ifndef RT_WAX_MODEL_H
#define RT_WAX_MODEL_H
#pragma interface

#include "RouterModel.h"

//////////////////////////////////////////////
//
// class RouterWaxman
// Derived class for Waxman model 
// Builds router-level topologies 
//
//////////////////////////////////////////////

class RouterWaxPar;

class RouterWaxman : public RouterModel {

 public:

  RouterWaxman(RouterWaxPar* par);
  ~RouterWaxman() { }
  Graph* Generate();
  string ToString();

 protected:

  void InterconnectNodes(Graph *g);

 private:

  double ProbFunc(Node* src, Node* dst);
  double alpha;
  double beta;

};

#endif /* RT_WAX_MODEL_H */


