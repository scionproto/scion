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
#ifndef BU_MODEL_H
#define BU_MODEL_H
#pragma interface

#include "Model.h" 

//////////////////////////////////////////////
//
// class BottomUpHierModel
// Derived class for hierarchical models that
// build topologies following a bottom-down approach
//
//////////////////////////////////////////////

class BottUpPar;

class BottomUpHierModel : public Model {
    
 public:
    
  BottomUpHierModel(BottUpPar* par);
  Graph* Generate(); 
  void GroupNodes(Graph* g);
  void SetModel(Model* m, int i) { assert(m != NULL); models[i] = m; }
  void RandomWalk(Graph* g, vector<Color>&, int last, int size, RandomVariable& U, int as, int& c);
  void AssignBW(Graph* g);
  int GetBWInterDist() { return BWInterdist; }
  double GetBWInterMin() { return BWIntermin; }
  double GetBWInterMax() { return BWIntermax; }
  string ToString();
    
 private:
    
  int nlevels;
  int ASNodes;
  vector<Model*> models;
  GroupingType group;
  AssignmentType at;
  BWDistType BWInterdist;
  double BWIntermin;
  double BWIntermax;

};


#endif /* MODEL_H */


