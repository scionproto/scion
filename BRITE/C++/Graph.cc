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
#pragma implementation "Graph.h"

#include "Graph.h"

Graph::Graph(int n) : nodes(n), adjList(n), incList(n) {

  assert(n > 0);
  numNodes = n;
  numEdges = 0;

}


void Graph::AddNode(Node* node, int index)
{

  assert(index >= 0 && index < numNodes); 

  try {

    nodes[index] = node;
    
  }

  catch (bad_alloc) {

    cout << "Graph::AddNode(): could not allocate node...\n" << flush;
    exit(0);
  
  }
}

void Graph::AddEdge(Edge *edge) {

  assert(edge != NULL);
  edges.insert(edges.end(), edge);
  numEdges++;

  /* SPRINT */
  edge->GetSrc()->AddIncEdge(edge);
  edge->GetDst()->AddIncEdge(edge);

}

void Graph::AddAdjListNode(int n1, int n2) {

  adjList[n1].insert(adjList[n1].begin(), n2);

}

void Graph::AddIncListNode(Edge* edge) {

  assert(edge != NULL);
  int n1 = edge->GetSrc()->GetId(); 
  int n2 = edge->GetDst()->GetId(); 

  incList[n1].insert(incList[n1].begin(), edge);
  incList[n2].insert(incList[n2].begin(), edge);

}

Node* Graph::GetNodePtr(int index) {

  assert(index >= 0 && index < numNodes);
  return nodes[index];

};

int Graph::GetNumNodes() { 

  return numNodes; 

}

int Graph::GetNumEdges() { 

  return numEdges; 

}

void Graph::SetNumNodes(int n) {
    
    assert(n > 0);
    numNodes = n; 

}

bool Graph::AdjListFind(int n1, int n2) {

  list<int>::iterator li;
  for (li = adjList[n1].begin(); li != adjList[n1].end(); li++) {
    if (*li == n2) {
      return 1;
    }
  }
  
  return 0;

}

void Graph::DFS(vector<Color>& color, vector<int>& pi, int u) {

  int v;

  color[u] = GRAY;
  list<int>::iterator li;

  for (li = adjList[u].begin(); li != adjList[u].end(); li++) {
    v = *li;
    if (color[v] == WHITE) {
      pi[v] = u;
      DFS(color, pi, v);
    }
  }

  color[u] = BLACK;

}
  
void Graph::RemoveEdge(int src, int dst) {

  /* Make sure edge exists */
  assert(AdjListFind(src,dst));

  /* Remove dst from src's adjacency list */
  list<int>::iterator adjl;
  for (adjl = adjList[src].begin(); adjl != adjList[src].end(); adjl++) {
    if (*adjl == dst) break;
  }

  adjList[src].remove(*adjl);

  /* Remove edge from list of Edges */
  list<Edge*>::iterator edgel;
  for (edgel = edges.begin(); edgel != edges.end(); edgel++) {
    if (((*edgel)->GetSrc()->GetId() == src) &&
	((*edgel)->GetDst()->GetId() == dst)) break;
  }

  edges.remove(*edgel);

  /* Remove edge (src,dst) or (dst,src) from incidency list of src */
  list<Edge*>::iterator incl;
  for (incl = incList[src].begin(); incl != incList[src].end(); incl++) {
    if ((((*incl)->GetSrc()->GetId() == src) && ((*incl)->GetDst()->GetId() == dst)) ||
	(((*incl)->GetSrc()->GetId() == dst) && ((*incl)->GetDst()->GetId() == src)))
      break;
  }
  
  incList[src].remove(*incl);

  /* Remove edge (src,dst) or (dst,src) from incidency list of dst */
  for (incl = incList[dst].begin(); incl != incList[dst].end(); incl++) {
    if ((((*incl)->GetSrc()->GetId() == src) && ((*incl)->GetDst()->GetId() == dst)) ||
	(((*incl)->GetSrc()->GetId() == dst) && ((*incl)->GetDst()->GetId() == src)))
      break;
  }

  incList[dst].remove(*incl);

  /* Decrease node degrees of src and dst */
  nodes[src]->SetInDegree(nodes[src]->GetInDegree() - 1);
  nodes[dst]->SetOutDegree(nodes[dst]->GetOutDegree() - 1);

}



