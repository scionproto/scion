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
#pragma implementation "ASWaxmanModel.h"

#include "ASWaxmanModel.h"

string ASWaxman::ToString() {
  
    //  char buf[80];
    //  ostrstream os((char*)buf, 80);
    //  string s;

  ostringstream os(ostringstream::out);

  os << "Model ( 3 ): " 
     << size << " "
     << Scale_1 << " "
     << Scale_2 << " "
     << (int)NodePlacement  << " "
     << (int)Growth << " "
     << m_edges << " "
     << alpha << " "
     << beta << " "
     << (int)GetBWDist() << " "
     << GetBWMin() << " "
     << GetBWMax() << '\0';

  return string(os.str());

}


ASWaxman::ASWaxman(ASWaxPar* par) {
  
  size = par->GetN();
  alpha = par->GetA();
  beta = par->GetB();
  Scale_1 = par->GetHS();
  Scale_2 = par->GetLS();
  assert(par->GetNP() == P_RANDOM || par->GetNP() == P_HT);
  NodePlacement = (PlacementType)par->GetNP();
  assert(par->GetIG() == G_ALL || par->GetIG() == G_INCR);
  Growth = (GrowthType)par->GetIG();;
  PrefConn = PC_NONE;
  ConnLoc = CL_OFF;
  assert(par->GetM() > 0);
  m_edges = par->GetM();  
  type = AS_WAXMAN;
  assert(par->GetBW() == BW_CONST ||
	 par->GetBW() == BW_UNIF ||
	 par->GetBW() == BW_EXP ||
	 par->GetBW() == BW_HT);
  SetBWDist((BWDistType)par->GetBW());
  SetBWMin(par->GetBWMin());
  SetBWMax(par->GetBWMax());
  
}

double ASWaxman::ProbFunc(Node* src, Node* dst) {
  
  double d, L;
  double x1, y1, x2, y2, dx, dy;
  
  /* Compute Euclidean distance */
  x1 = ((RouterNodeConf*)(src->GetNodeInfo()))->GetCoordX();
  y1 = ((RouterNodeConf*)(src->GetNodeInfo()))->GetCoordY();
  x2 = ((RouterNodeConf*)(dst->GetNodeInfo()))->GetCoordX();
  y2 = ((RouterNodeConf*)(dst->GetNodeInfo()))->GetCoordY();
  dx = x1 - x2;
  dy = y1 - y2;
  d =  sqrt(dx*dx + dy*dy);
  
  /* Maximum distance between nodes */
  L = sqrt(2.0) * Scale_1;  
  
  /* return interconnection probability */
  return  alpha * exp(-1.0*(d/(beta * L)));
  
}


Graph* ASWaxman::Generate() {
  
  Graph* graph;
  
  try {

      graph = new Graph(size);

  }
  catch (bad_alloc) {
    
    cerr << "ASWaxman::Generate(): Cannot create new graph...\n" << flush;
    exit(0);
    
  }
  
  /* Place nodes into plane */
  cout << "Placing nodes...\n" << flush;
  PlaceNodes(graph);
  
  /* Build topology graph using Waxman */
  cout << "Interconnect nodes...\n" << flush;
  InterconnectNodes(graph);
  
  /* Assign bandwidths to edges */
  cout << "Assigning bandwidth...\n" << flush;
  AssignBW(graph);

  return graph;

}

void ASWaxman::InterconnectNodes(Graph* g) {

  int num_connected, n1, n2, edges_added;
  Node *src, *dst;
  double p;
  RandomVariable U(s_connect);
  
  int n = size;

  switch (GetGrowthType()) {

  case G_ALL: 
    /* Pick nodes randomly and interconnect them 
     * Keep track of connected nodes to determine 
     * when to finish. Nodes can be selected more than
     * once.  
     */ 
    num_connected = 0;
    while (num_connected < n) {

      /* Randomly pick two nodes */
      n1 = (int)floor(U.GetValUniform((double)n));
      src = g->GetNodePtr(n1);
      edges_added = 0;

      while ((edges_added < m_edges) && (num_connected < n)) {

	/* Pick dest randomly */
	n2 = (int)floor( U.GetValUniform((double)n));
	if (n1 == n2) continue;

	/* No multiple links between two nodes */
	if (g->AdjListFind(n1, n2)) continue;

	/* Grab dest node pointer */
	dst = g->GetNodePtr(n2);
	
	/* Determine probability of interconnecting src to dst */
	p = ProbFunc(src, dst);

	/* flip coin */
	if (U.GetValUniform() < p) {

	  /* Create new Edge */
	  try {
	    Edge* edge = new Edge(src, dst);
	    g->AddEdge(edge);
	    ASEdgeConf* as_conf = new ASEdgeConf();	    
	    as_conf->SetEdgeType(EdgeConf::AS_EDGE);
	    edge->SetConf(as_conf);
	  }
	  catch (bad_alloc) {
	    cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
	    exit(0);
	  }

	  /* Update adjacency lists */
	  g->AddAdjListNode(n1,n2);
	  g->AddAdjListNode(n2,n1);
	  
	  /* Update In and Outdegrees for src */
	  src->SetInDegree(src->GetInDegree() + 1);
	  src->SetOutDegree(src->GetOutDegree() + 1);
	  if (src->GetOutDegree() == 1) {
	    num_connected++;
	  }

  	  /* Update In and Outdegrees for dst */
	  dst->SetInDegree(dst->GetInDegree() + 1);
	  dst->SetOutDegree(dst->GetOutDegree() + 1);
	  if (dst->GetOutDegree() == 1) {
	    num_connected++;
	  }
	  
	  edges_added++;
	}
      }
    }
    cout << "Num nodes connected: " << num_connected << "\n" << flush;
    break;

  case G_INCR:
    /* 
     * Select a node randomly to join the network and interconnect it
     * to some nodes in the existing network. Once a node has been selected
     * and joined the network it will not be selected again except as a target
     * node. Since the nodes were placed randomly, selecting them sequentially
     * from the nodes array is equivalent to picking them randomly.
     * Since m edges need to be added per each joining node, and those m edges should
     * go only to nodes that already belong to the network, we will assume that the
     * network starts with m nodes and start the interconnection process from m
     * ro NumNodes. In order to ut edges also from the first m nodes to the rest,
     * at the end we will "connect" them as we did in the previous case.
     *
     */

    for (int i = m_edges; i < g->GetNumNodes(); i++) {

      src = g->GetNodePtr(i);      
      edges_added = 0;
      while (edges_added < m_edges) {

	if (src->GetOutDegree() >= g->GetNumNodes() - m_edges) 
	  break;
      
	n2 = (int)floor( U.GetValUniform((double)i));
	if (i == n2) continue;

	/* No multiple links between two nodes */
	if (g->AdjListFind(i, n2)) continue;

	/* Grab dest node pointer */
	dst = g->GetNodePtr(n2);
	
	/* Determine probability of interconnecting src to dst */
	p = ProbFunc(src, dst);

	/* flip coin */
	if (U.GetValUniform() < p) {

	  /* Create new Edge */
	  try {

	    Edge* edge = new Edge(src, dst);
	    g->AddEdge(edge);
	    ASEdgeConf* as_conf = new ASEdgeConf();
	    as_conf->SetEdgeType(EdgeConf::AS_EDGE);
	    edge->SetConf(as_conf);
	    
	  }
	  catch (bad_alloc) {
	    cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
	    exit(0);
	  }

	  /* Update adjacency lists */
	  g->AddAdjListNode(i,n2);
	  g->AddAdjListNode(n2,i);
	  
	  /* Update In and Outdegrees for src */
	  src->SetInDegree(src->GetInDegree() + 1);
	  src->SetOutDegree(src->GetOutDegree() + 1);

  	  /* Update In and Outdegrees for dst */
	  dst->SetInDegree(dst->GetInDegree() + 1);
	  dst->SetOutDegree(dst->GetOutDegree() + 1);

	  edges_added++;
	}
      }

    }

    for (int i = 0; i < m_edges; i++) {

      src = g->GetNodePtr(i);      
      edges_added = 0;
      while (edges_added < m_edges) {
      
	if (src->GetOutDegree() >= g->GetNumNodes() - m_edges) 
	  break;

	/* Randomly pick a node from m_edges to NumNodes */
	n2 = (int)floor( m_edges + U.GetValUniform((double)(g->GetNumNodes() - m_edges)));
	if (i == n2) continue;

	/* No multiple links between two nodes */
	if (g->AdjListFind(i, n2)) continue;

	/* Grab dest node pointer */
	dst = g->GetNodePtr(n2);
	
	/* Determine probability of interconnecting src to dst */
	p = ProbFunc(src, dst);

	/* flip coin */
	if (U.GetValUniform() < p) {

	  /* Create new Edge */
	  try {

	    Edge* edge = new Edge(src, dst);
	    g->AddEdge(edge);
	    ASEdgeConf* as_conf = new ASEdgeConf();
	    as_conf->SetEdgeType(EdgeConf::AS_EDGE);
	    edge->SetConf(as_conf);

	  }
	  catch (bad_alloc) {
	    cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
	    exit(0);
	  }
	  
	  /* Update adjacency lists */
	  g->AddAdjListNode(i,n2);
	  g->AddAdjListNode(n2,i);
	  
	  /* Update In and Outdegrees for src */
	  src->SetInDegree(src->GetInDegree() + 1);
	  src->SetOutDegree(src->GetOutDegree() + 1);
	  if (src->GetOutDegree() == 1) {
	    num_connected++;
	  }
	  
  	  /* Update In and Outdegrees for dst */
	  dst->SetInDegree(dst->GetInDegree() + 1);
	  dst->SetOutDegree(dst->GetOutDegree() + 1);
	  if (dst->GetOutDegree() == 1) {
	    num_connected++;
	  }
	  
	  edges_added++;
	}
      }
    }
    break;

  default:
    cout << "Invalid Growth type model...\n" << flush;
    assert(0);
    
  }
}

