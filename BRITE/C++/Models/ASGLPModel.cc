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
#pragma implementation "ASGLPModel.h"

#include "ASGLPModel.h"


ASGLP::ASGLP(ASGLPPar* par) {

  size = par->GetN();
  Scale_1 = par->GetHS();
  Scale_2 = par->GetLS();
  assert(par->GetNP() == P_RANDOM || par->GetNP() == P_HT);
  NodePlacement = (PlacementType)par->GetNP();
  Growth = G_INCR;
  PrefConn = PC_BARABASI;
  ConnLoc = CL_OFF;
  assert(par->GetM() > 0);
  m_edges = par->GetM();
  SumDj = 0;
  type = AS_GLP;
  assert(par->GetBW() == BW_CONST ||
	 par->GetBW() == BW_UNIF ||
	 par->GetBW() == BW_EXP ||
	 par->GetBW() == BW_HT);
  SetBWDist((BWDistType)par->GetBW());
  SetBWMin(par->GetBWMin());
  SetBWMax(par->GetBWMax());
  P = par->GetP();
  BETA = par->GetBETA();
  
}
 
string ASGLP::ToString() {
  
    //  char buf[80];
    //  ostrstream os((char*)buf, 80);
    //  string s;

  ostringstream os(ostringstream::out);

  os << "Model ( 12 ): " 
     << size << " "
     << Scale_1 << " "
     << Scale_2 << " "
     << (int)NodePlacement  << " "
     << m_edges << " "
     << (int)GetBWDist() << " "
     << GetBWMin() << " "
     << GetBWMax() << '\0';

  return string(os.str());

}

void ASGLP::InterconnectNodes(Graph *g) {
  
  int edges_added;
  RandomVariable U(s_connect);
  
  cout << "ASGLP: Interconnecting nodes...\n" << flush;

  SumDj = 0;

  /* Start with m nodes connected through m - 1 edges */
  for (int i = 1; i <= m_edges; i++) {

    Node* src = g->GetNodePtr(i - 1);
    Node* dst = g->GetNodePtr(i);
    assert(src != NULL && dst != NULL);

    /* Create new Edge */
    try {
  
      Edge* edge = new Edge(src, dst);
      g->AddEdge(edge);
      ASEdgeConf* as_conf = new ASEdgeConf();
      as_conf->SetEdgeType(EdgeConf::AS_EDGE);
      edge->SetConf(as_conf);

    }
    catch (bad_alloc) {
      cerr << "RouterGLP::Interconnect(): Cannot allocate new edge...\n" << flush;
      exit(0);
    }      
    
    /* Update adjacency lists */
    g->AddAdjListNode(i - 1, i);
    g->AddAdjListNode(i, i - 1);
    
    /* Update In and Outdegrees for src */
    src->SetInDegree(src->GetInDegree() + 1);
    src->SetOutDegree(src->GetOutDegree() + 1);
    SumDj++;
    
    /* Update In and Outdegrees for dst */
    dst->SetInDegree(dst->GetInDegree() + 1);
    dst->SetOutDegree(dst->GetOutDegree() + 1);
    SumDj++;
    
  }

  /* Initialize array of node outdegrees */
  vector<double> d(g->GetNumNodes());
  for (int i = 0; i < g->GetNumNodes(); i++) {
    d[i] = (double)g->GetNodePtr(i)->GetOutDegree();
  }
  
  int added_nodes = m_edges;
  /* Add rest of nodes */
  while (added_nodes < g->GetNumNodes() - 1) {

    /* Flip coin to decide to add links or adding a new node */
    double r = U.GetValUniform();

    /* If graph is nearly complete, don't add links, just add nodes */
    int maxedges = (added_nodes * (added_nodes - 1)/2) - m_edges;
    if (g->GetNumEdges() >= maxedges) {
      r = P + 0.001; /* force node addition */
    }

    if (r < P) { /* add m_egdes links */
      
      int added_edges = 0;
      while (added_edges < m_edges) {

	if (added_nodes == m_edges) break;
	double v = U.GetValUniform();
	double last = 0.0;
	int src_index;
	for (src_index = 0; src_index < added_nodes; src_index++) {
	  last += (d[src_index] - BETA)/(SumDj - added_nodes * BETA);
	  if (v < last) break;
	}

	v = U.GetValUniform();
	int dst_index = 0;
	for (dst_index = 0; dst_index < added_nodes; dst_index++) {
	  last += (d[dst_index] - BETA)/(SumDj - added_nodes * BETA);
	  if (v < last) break;
	}	
	
	if (src_index == dst_index) continue;
	if ((g->AdjListFind(src_index, dst_index)) ||
	    (g->AdjListFind(dst_index, src_index))) continue;

	Node* src = g->GetNodePtr(src_index);
	Node* dst = g->GetNodePtr(dst_index);
	assert(src != NULL && dst != NULL);

	/* Create new Edge */
	try {
	  
	  Edge* edge = new Edge(src, dst);
	  g->AddEdge(edge);
	  ASEdgeConf* as_conf = new ASEdgeConf();
	  as_conf->SetEdgeType(EdgeConf::AS_EDGE);
	  edge->SetConf(as_conf);
	  
	}
	catch (bad_alloc) {
	  cerr << "RouterGLP::Interconnect(): Cannot allocate new edge...\n" << flush;
	  exit(0);
	}      
	
	/* Update adjacency lists */
	g->AddAdjListNode(src_index, dst_index);
	g->AddAdjListNode(dst_index, src_index);
	
	/* Update In and Outdegrees for src */
	src->SetInDegree(src->GetInDegree() + 1);
	src->SetOutDegree(src->GetOutDegree() + 1);
	SumDj++;
    
	/* Update In and Outdegrees for dst */
	dst->SetInDegree(dst->GetInDegree() + 1);
	dst->SetOutDegree(dst->GetOutDegree() + 1);
	SumDj++;
	
	added_edges += 1;

      }

    }else {  /* Add new node and m_edges from it */

      added_nodes += 1;
      Node* src = g->GetNodePtr(added_nodes);      
      edges_added = 0;
      
      while (edges_added < m_edges) {
	
	/* Flip coin to select target node*/
	double u = U.GetValUniform();
	
	int k;
	double last = 0.0;
	for (k = 0; k < added_nodes; k++) {
	  last += d[k]/SumDj;
	  if (u <= last) break;
	}

	if (k == added_nodes ) continue;
	
	/* No multiple links between two nodes */
	if (g->AdjListFind(added_nodes, k)) continue;
	
	/* Grab dest node pointer */
	Node* dst = g->GetNodePtr(k);
	
	/* Create new Edge */
	try {
	  
	  Edge* edge = new Edge(src, dst);
	  g->AddEdge(edge);
	  g->AddIncListNode(edge);
	  ASEdgeConf* as_conf = new ASEdgeConf();
	  as_conf->SetEdgeType(EdgeConf::AS_EDGE);
	  edge->SetConf(as_conf);
	  
	}
	catch (bad_alloc) {
	  cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
	  exit(0);
	}
	
	/* Update adjacency lists */
	g->AddAdjListNode(added_nodes,k);
	g->AddAdjListNode(k, added_nodes);
	
	/* Update In and Outdegrees for dst */
	dst->SetInDegree(dst->GetInDegree() + 1);
	dst->SetOutDegree(dst->GetOutDegree() + 1);
	SumDj++;
	d[k]++;
	edges_added++;
	
      }

      /* Update In and Outdegrees for src */
      src->SetInDegree(src->GetInDegree() + m_edges);
      src->SetOutDegree(src->GetOutDegree() + m_edges);
      d[added_nodes] += m_edges;
      SumDj += m_edges;
    
    }

  }

  cout << "\n" << flush;
  cout << "Done interconnecting...\n" << flush;

}

