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
#pragma implementation "ASBarabasiAlbertModel-1.h"

#include "ASBarabasiAlbertModel-1.h"


ASBarabasiAlbert_1::ASBarabasiAlbert_1(ASBarabasiAlbert_1_Par* par) {

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
  type = AS_BARABASI_1;
  assert(par->GetBW() == BW_CONST ||
	 par->GetBW() == BW_UNIF ||
	 par->GetBW() == BW_EXP ||
	 par->GetBW() == BW_HT);
  SetBWDist((BWDistType)par->GetBW());
  SetBWMin(par->GetBWMin());
  SetBWMax(par->GetBWMax());
  
}
 
string ASBarabasiAlbert_1::ToString() {
  
    //  char buf[80];
    //  ostrstream os((char*)buf, 80);
    //  string s;

  ostringstream os(ostringstream::out);

  os << "Model ( 4 ): " 
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



void ASBarabasiAlbert_1::InterconnectNodes(Graph *g) {

  int edges_added;
  Node *src, *dst;
  double p;
  RandomVariable U(s_connect);

  /* 
   * Select a node randomly to join the network and interconnect it
   * to some nodes in the existing network. Once a node has been selected
   * and joined the network it will not be selected again except as a target
   * node. Since the nodes were placed randomly, selecting them sequentially
   * from the nodes array is equivalent to picking them randomly.
   * Since m edges need to be added per each joining node, and those m edges should
   * go only to nodes that already belong to the network, we will assume that the
   * network starts with m nodes and start the interconnection process from m
   * to NumNodes. In order to put edges also from the first m nodes to the rest,
   * at the end we will "connect" them as we did in the previous case.
   *
   */
  cout << "ASBarabasiAlbert-1: Interconnecting nodes...\n";

  SumDj = 0;
  for (int i = 0; i <= m_edges; i++) {
    for (int j = i + 1; j <= m_edges; j++) {
      
      src = g->GetNodePtr(i);      
      dst = g->GetNodePtr(j);      
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
	cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
	exit(0);
      }
      
      /* Update adjacency lists */
      g->AddAdjListNode(i,j);
      g->AddAdjListNode(j,i);
      
      /* Update In and Outdegrees for src */
      src->SetInDegree(src->GetInDegree() + 1);
      src->SetOutDegree(src->GetOutDegree() + 1);
      SumDj++;
	
      /* Update In and Outdegrees for dst */
      dst->SetInDegree(dst->GetInDegree() + 1);
      dst->SetOutDegree(dst->GetOutDegree() + 1);
      SumDj++;
	  
    }
  }

  vector<double> d(g->GetNumNodes());
  for (int i = 0; i < g->GetNumNodes(); i++) {
    d[i] = (double)g->GetNodePtr(i)->GetOutDegree();
  }

  for (int i = m_edges + 1; i < g->GetNumNodes(); i++) {
    
    src = g->GetNodePtr(i);      
    edges_added = 0;

    while (edges_added < m_edges) {

      /* Flip coin */
      p = U.GetValUniform();

      int k;
      double last = 0.0;
      for (k = 0; k < g->GetNumNodes(); k++) {
	last += d[k]/SumDj;
	if (p <= last) break;
      }
      if (k == i) continue;
      
      /* No multiple links between two nodes */
      if (g->AdjListFind(i, k)) continue;
      
      /* Grab dest node pointer */
      dst = g->GetNodePtr(k);
      
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
      g->AddAdjListNode(i,k);
      g->AddAdjListNode(k,i);
      
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
    d[i] += m_edges;
    SumDj += m_edges;
    if (i%1000 == 0) 
      cout << "." << flush;
  }

  if (g->GetNumNodes() > 1000) cout << "\n" << flush;

}


