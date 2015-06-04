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
#ifndef TD_MODEL_H
#define TD_MODEL_H
#pragma interface

#include "Model.h"

//////////////////////////////////////////////////
//
// class TopDownHierModel
// Derived class for hierarchical models that
// build topologies following a top-down approach
//
///////////////////////////////////////////////////

class TopDownPar;

class TopDownHierModel : public Model {

 public:

  TopDownHierModel(TopDownPar* par);

  int GetK() { return k; }
  int GetLevels() { return nlevels; }
  void SetModel(Model* m, int i) { assert(m != NULL); models[i] = m; }
  EdgeConnType GetEdgeConnType() { return edge_conn_type; }
  Graph* Generate(); 
  Graph* FlattenGraph(Graph* g);
  void InterConnectBorders(Graph* g, Graph* flat_g);
  int GetFlatRandomNode(int as, Graph* g, Graph* flat_g, vector<int>& p, RandomVariable& U);
  int GetFlatSmallest(int, Graph*, Graph*, vector<int>& p); 
  int GetFlatSmallestNoLeaf(int, Graph*, Graph*, vector<int>& p);
  int GetFlatSmallestK(int ASid, Graph* g, Graph* flat_g, vector<int>& p);
  int GetBWInterDist() { return BWInterdist; }
  double GetBWInterMin() { return BWIntermin; }
  double GetBWInterMax() { return BWIntermax; }
  int GetBWIntraDist() { return BWIntradist; }
  double GetBWIntraMin() { return BWIntramin; }
  double GetBWIntraMax() { return BWIntramax; }
  string ToString();

 private:
    
  int nlevels;
  vector<Model*> models;
  int k;
  EdgeConnType edge_conn_type;
  BWDistType BWInterdist;
  double BWIntermin;
  double BWIntermax;
  BWDistType BWIntradist;
  double BWIntramin;
  double BWIntramax;
  
};

#endif /* TD_MODEL_H */


