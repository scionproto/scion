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
#pragma implementation "ASBarabasiAlbertModel.h"

#include "ASBarabasiAlbertModel.h"


inline double ASBarabasiAlbert::ProbFunc(Node* dst) {

  /* return interconnection probability */
  assert(SumDj > 0);
  return  dst->GetOutDegree() / (double)SumDj;
  
}
 
Graph* ASBarabasiAlbert::Generate() {

  Graph* graph;

  try {
    if (GetPlacementType() == P_HT) {
      graph = new Graph((int)(size * 1.1));
    }else {
      graph = new Graph(size);
    }
  }
  catch (bad_alloc) {
    cerr << "ASBarabasiAlbert::Generate(): Cannot create new graph...\n" << flush;
    exit(0);
  }

  /* Place nodes into plane */
  cout << "Placing nodes...\n" << flush;
  PlaceNodes(graph);

  /* Build topology grasph using BarabasiAlbert */
  cout << "Interconnecting nodes...\n" << flush;
  InterconnectNodes(graph);
  
  /* Assign bandwidths to edges */
  cout << "Assigning bandwidths...\n" << flush;
  AssignBW(graph);

  return graph;

}





