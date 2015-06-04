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
#pragma implementation "Model.h"

#include "Model.h"

unsigned short int Model::s_places[3] = {0,0,0};
unsigned short int Model::s_connect[3] = {0,0,0};
unsigned short int Model::s_edgeconn[3] = {0,0,0};
unsigned short int Model::s_grouping[3] = {0,0,0};
unsigned short int Model::s_assignment[3] = {0,0,0};
unsigned short int Model::s_bandwidth[3] = {0,0,0};
vector<PlaneRowAdjNode*> Model::row_ocup(10000);

void PlaneRowAdjNode::ColInsert(int ty) {
  
  row_adjlist.insert(row_adjlist.end(), ty);
  
};

bool PlaneRowAdjNode::ColFind(int ty) {
  
  list<int>::iterator cl;

  cl = find(row_adjlist.begin(), row_adjlist.end(), ty);
  if (cl == row_adjlist.end()) {

    ColInsert(ty);
    return false;

  }

  return true;

}


bool Model::PlaneCollision(int tx, int ty) {

  bool found = false;

  if (tx >= (int)row_ocup.size()) { 

    row_ocup.resize(tx + 1);

  }else {

    if (row_ocup[tx] != NULL) {

      found = true;

    }

  }

  if (!found) {

    PlaneRowAdjNode* rowadjnode = new PlaneRowAdjNode(tx);
    rowadjnode->ColInsert(ty);
    row_ocup[tx] = rowadjnode;
    return false;
  }
    
  return row_ocup[tx]->ColFind(ty);

}



