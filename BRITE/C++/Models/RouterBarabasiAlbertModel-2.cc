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
#pragma implementation "RouterBarabasiAlbertModel-2.h"

#include "RouterBarabasiAlbertModel-2.h"

RouterBarabasiAlbert_2::RouterBarabasiAlbert_2(RouterBarabasiAlbert_2_Par* par)
{
  
  size = par->GetN();
  Scale_1 = par->GetHS();
  Scale_2 = par->GetLS();
  assert(par->GetNP() == P_RANDOM || par->GetNP() == P_HT);
  NodePlacement = (PlacementType)par->GetNP();
  Growth = G_INCR;
  PrefConn = PC_NONE;
  ConnLoc = CL_OFF;
  assert(par->GetM() > 0);
  m_edges = par->GetM();
  SumDj = 0;
  type = RT_BARABASI_2;
  assert(par->GetBW() == BW_CONST ||
	 par->GetBW() == BW_UNIF ||
	 par->GetBW() == BW_EXP ||
	 par->GetBW() == BW_HT);
  SetBWDist((BWDistType)par->GetBW());
  SetBWMin(par->GetBWMin());
  SetBWMax(par->GetBWMax());
  P = par->GetP();
  Q = par->GetQ();
  
}

string RouterBarabasiAlbert_2::ToString() {
  
    //  char buf[80];
    //  ostrstream os((char*)buf, 80);
    //  string s;

  ostringstream os(ostringstream::out);

  os << "Model ( 9 ): " 
     << size << " "
     << Scale_1 << " "
     << Scale_2 << " "
     << (int)NodePlacement  << " "
     << m_edges << " "
     << GetBWDist() << " "
     << GetBWMin() << " "
     << GetBWMax() << '\0';

  return string(os.str());

}



void RouterBarabasiAlbert_2::InterconnectNodes(Graph *g) {

  int edges_added;
  Node *src, *dst;
  RandomVariable U(s_connect);
  
  /* BarabasiAlbert2: on each step, the model either adds a new node
   * and m edges, adds m edges, or rewires m edges already present in
   * the topology. The model has two additional parameters repreenting
   * probabilities p and q. At each step a coin is flipped to get a
   * random number r. If r < p, then m edges (m <= m0) are added to
   * the topology. If p < r < p + q, then rewire m existing
   * edges. Otherwise, add a new node and m edges as in the
   * BarabasiAlbert model. The topology starts a clique of m_edges
   * nodes. 
   */

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
   */

  cout << "RouterBarabasiAlbert-2: Interconnecting nodes...\n";
  
  SumDj = 0;
  /* Create fully connected clique with m_edges nodes */
  for (int i = 0; i <= m_edges; i++) {
    for (int j = i + 1; j <= m_edges; j++) {
      
      src = g->GetNodePtr(i);      
      dst = g->GetNodePtr(j);      
      assert(src != NULL && dst != NULL);
      
      /* Create new Edge */
      try {

	Edge* edge = new Edge(src, dst);
	g->AddEdge(edge);
	RouterEdgeConf* rt_conf = new RouterEdgeConf(edge->Length());
	rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	edge->SetConf(rt_conf);

      }
      catch (bad_alloc) {
	cerr << "RouterBarabasiAlbert-2->Interconnect(): Cannot allocate new edge...\n" << flush;
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
  
  int added_nodes = m_edges;
  
  while (added_nodes < g->GetNumNodes() - 1) {
    
    /* Coin flip to decide on action to be taken */
    double r = U.GetValUniform();
    
    /* if graph is at or near-clique,  don't rewire or add, just add nodes */
    int maxEdges = (added_nodes * (added_nodes - 1) / 2) - ( m_edges + 1);
    if (g->GetNumEdges() >= maxEdges) {
      
      r = P + Q + 0.001;  /* this will trigger a node addition */
      
    }
    
    if (r < P) { /* Add m new edges */
      
      int num_edges_added = 0;
      while (num_edges_added < m_edges) {
	
	double u = U.GetValUniform();
	double last = 0.0;
	
	int srcind;
	for (srcind =  0; srcind < added_nodes; srcind++) {
	  last += d[srcind]/SumDj;
	  if (u < last) break;
	}
	
	u = U.GetValUniform();
	last = 0.0;
	
	int dstind;
	for (dstind = 0; dstind < added_nodes; dstind++) {
	  last += d[dstind]/SumDj;
	  if (u < last) break;
	}	
	
	if (srcind == dstind) continue;
	if (g->AdjListFind(srcind,dstind) || 
	    g->AdjListFind(srcind, dstind)) continue;
	
	Node* src = g->GetNodePtr(srcind);
	Node* dst = g->GetNodePtr(dstind);
	
	/* Add edge to the graph */
	try {

	  Edge* edge = new Edge(src, dst);
	  g->AddEdge(edge);
	  RouterEdgeConf* rt_conf = new RouterEdgeConf(edge->Length());
	  rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	  edge->SetConf(rt_conf);
	}
	catch (bad_alloc) {
	  cerr << "RouterBarabasiAlbert-2->Interconnect(): Cannot allocate new edge...\n" << flush;
	  exit(0);
	}	
	
	d[srcind]++;
	d[dstind]++;
	
	SumDj += 2;

	num_edges_added += 1;
	
      }
      
    }
    
    if ((r > P) && (r < P + Q)) { /* rewire m edges */
      
      int num_edges_rewired = 0;
      
      while (num_edges_rewired < m_edges) {
	
	/* Select random source node */
	int random_src_index = (int)U.GetValUniform(0, added_nodes);
	int adjlist_size = g->GetAdjListSize(random_src_index);
	if (adjlist_size < 1) break;
	vector<int> neighbors(adjlist_size);
	list<int>::iterator adjl;
	int pos = 0;
	for (adjl = g->adjList[random_src_index].begin(); 
	     adjl != g->adjList[random_src_index].end(); adjl++) {

	  neighbors[pos++] = *adjl;
	}
	
	/* Select destination randomly among neighbors of random_src */
	int random_dst_index = 0;
	if (adjlist_size == 1) {
	  random_dst_index = neighbors[0];
	}else {
	  random_dst_index = neighbors[(int)U.GetValUniform(0, adjlist_size)];
	}
	
	/* Edge (random_src_index, random_dst_index will be rewired */
	/* Select target of rewiring */
	int dstind; 
	double u = U.GetValUniform();
	double last = 0.0;
	for (int dstind =  0; dstind < added_nodes; dstind++) {
	  last += d[dstind]/SumDj;
	  if (u < last) break;
	} 
	
	if (dstind == random_src_index) continue;
	if (g->AdjListFind(random_src_index, dstind)) continue;
	
	/* Remove edge (random_src_index, random_dst_index) and add edge
	 * (random_src_index, dstind) */
	g->RemoveEdge(random_src_index, random_dst_index);
	d[random_dst_index] -= 1;
	
	Node* src = g->GetNodePtr(random_src_index);
	Node* dst = g->GetNodePtr(dstind);

	/* Add edge to the graph */
	try {
	  Edge* edge = new Edge(src, dst);
	  g->AddEdge(edge);
	  RouterEdgeConf* rt_conf = new RouterEdgeConf(edge->Length());
	  rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	  edge->SetConf(rt_conf);
	}
	catch (bad_alloc) {
	  cerr << "RouterBarabasiAlbert-2->Interconnect(): Cannot allocate new edge...\n" << flush;
	  exit(0);
	}	
	
	d[dstind]++;

	num_edges_rewired += 1;

      }

    }
	
	

    if (r >= P + Q) { /* Add new node and m edges */

      added_nodes += 1;
      src = g->GetNodePtr(added_nodes);      
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
	dst = g->GetNodePtr(k);
	
	/* Create new Edge */
	try {
	  
	  Edge* edge = new Edge(src, dst);
	  g->AddEdge(edge);
	  g->AddIncListNode(edge);
	  RouterEdgeConf* rt_conf = new RouterEdgeConf(edge->Length());
	  rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	  edge->SetConf(rt_conf);
	  
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

}


