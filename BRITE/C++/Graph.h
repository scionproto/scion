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
#ifndef GRAPH_H
#define GRAPH_H
#pragma interface

#include "Node.h"
#include "Edge.h"

class Node;
class Edge;

class Graph {

  friend class Topology;
  friend class BottomUpHierModel;
  friend class TopDownHierModel;
  friend class RouterModel;
  friend class ASModel;
  friend class ASBarabasiAlbert_2;
  friend class RouterBarabasiAlbert_2;
  friend class ImportedFileModel;
  friend class Analysis;

 public:
  
  Graph(int size);

  void AddNode(Node* node, int i);
  void AddEdge(Edge* edge);
  void AddAdjListNode(int n1, int n2);
  void AddIncListNode(Edge* edge);
  Node* GetNodePtr(int index);
  int GetAdjListSize(int u) { return adjList[u].size(); }
  int GetIncListSize(int u) { return incList[u].size(); }
  int GetEdgeListSize() { return edges.size(); }
  int GetNumNodes();
  int GetNumEdges();
  void SetNumNodes(int n);
  bool AdjListFind(int n1, int n2);
  void DFS(vector<Color>&, vector<int>&, int u);
  void RemoveEdge(int src, int dst);

 protected:

  int numNodes;
  int numEdges;
  vector<Node*> nodes;
  list<Edge*> edges;
  vector< list<int> > adjList;
  vector< list<Edge*> > incList;

};


#endif /* GRAPH_H */
