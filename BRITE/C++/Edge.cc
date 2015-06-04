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
#pragma implementation "Edge.h"

#include "Edge.h"

int Edge::edge_count = 0;

Edge::Edge(Node* s, Node* d) 
{

  assert(s != NULL && d != NULL);
  src = s;
  dst = d;
  color = BLACK;
  conf = NULL;
  id = edge_count;
  edge_count += 1;
  directed = false; /* Undirected by default */

}

Edge::~Edge() {

  delete src;
  delete dst;
  delete conf;

}

ASEdgeConf::ASEdgeConf() {

  as_edge_type = AS_NONE;
  SetBW(0.0);
  SetWeight(7.9);

}



RouterEdgeConf::RouterEdgeConf(double len) {

  rt_edge_type = RT_NONE;
  length = len;
  SetBW(0.0);
  delay = 1000.0 * (1000.0 * length)/SPEED_OF_LIGHT;
  SetWeight(7.9);

}

/* Euclidean distance between two vertices */
double Edge::Length() {

  double dx, dy;
  double foo;

  dx = (double) src->GetNodeInfo()->GetCoordX() -  (double)dst->GetNodeInfo()->GetCoordX();
  dy = (double) src->GetNodeInfo()->GetCoordY() -  (double)dst->GetNodeInfo()->GetCoordY();
  foo = (dx*dx) + (dy*dy);
  return sqrt(foo);

}
