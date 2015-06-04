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
#pragma implementation "Topology.h"

#include "Topology.h"
#include "Models/Model.h"
#include "Models/RouterModel.h"
#include "Models/ASModel.h"
#include "Models/RouterWaxmanModel.h"
#include "Models/RouterBarabasiAlbertModel-1.h"
#include "Models/RouterBarabasiAlbertModel-2.h"
#include "Models/RouterGLPModel.h"
#include "Models/ASWaxmanModel.h"
#include "Models/ASBarabasiAlbertModel-1.h"
#include "Models/ASBarabasiAlbertModel-2.h"
#include "Models/ASGLPModel.h"
#include "Models/ImportedFileModel.h"
#include "Models/TopDownHierModel.h"
#include "Models/BottomUpHierModel.h"

Topology::Topology(Model* model) 
{
  m = model;
  g = m->Generate();
  assert(g != NULL);

}

inline int Topology::GetNumNodes() {
  assert(g != NULL);
  return g->Graph::GetNumNodes();
}
 
inline int Topology::GetNumEdges() { 
  assert(g != NULL);
  return g->Graph::GetNumEdges(); 
}


bool Topology::IsConnected() {

  vector<Color> color(g->GetNumNodes());
  vector<int> pi(g->GetNumNodes());

  for (int i = 0; i < GetNumNodes(); i++) {
    color[i] = WHITE;
  }

  g->DFS(color, pi, 0);

  int conn = 1;
  for (int i = 0; i < g->GetNumNodes(); i++) {
    if (color[i] == WHITE) {
      return false;
    }
  }

  return conn;

}


void Topology::BriteOutput(char* filename) {

  ofstream outfile;
  string actual_name = filename;
  actual_name += ".brite";
  outfile.open(actual_name.c_str(), ios::out);
  outfile.setf(ios::fixed, ios::floatfield);
  outfile.precision(2);
  assert(outfile);

  outfile << "Topology: ( " << g->GetNumNodes() << " Nodes, "
	  << g->GetNumEdges() << " Edges )\n";

  switch (m->GetType()){

  case RT_WAXMAN:
    outfile << ((RouterWaxman*)m)->ToString() << "\n\n";
    break;

  case RT_BARABASI_1:
    outfile << ((RouterBarabasiAlbert_1*)m)->ToString() << "\n\n";
    break;

  case RT_BARABASI_2:
    outfile << ((RouterBarabasiAlbert_2*)m)->ToString() << "\n\n";
    break;

  case RT_GLP:
    outfile << ((RouterGLP*)m)->ToString() << "\n\n";
    break;

  case AS_WAXMAN:
    outfile << ((ASWaxman*)m)->ToString() << "\n\n";
    break;

  case AS_BARABASI_1:
    outfile << ((ASBarabasiAlbert_1*)m)->ToString() << "\n\n";
    break;

  case AS_BARABASI_2:
    outfile << ((ASBarabasiAlbert_2*)m)->ToString() << "\n\n";
    break;

  case AS_GLP:
    outfile << ((ASGLP*)m)->ToString() << "\n\n";
    break;

  case TD_HIER:
    outfile << ((TopDownHierModel*)m)->ToString() << "\n\n";
    break;

  case BU_HIER:
    outfile << ((BottomUpHierModel*)m)->ToString() << "\n\n";
    break;

  case IF_ROUTER:
  case IF_AS:
    outfile << ((ImportedFileModel*)m)->ToString() << "\n\n";
    break;

  default:
    cerr << "Topology::Output(): Invalid model type (" << (int)m->GetType() << ")  passed....\n";
    exit(0);

  }

  outfile << "Nodes: (" << g->GetNumNodes() << ")" << "\n";
  for (int i = 0; i < g->GetNumNodes(); i++) {

    outfile << g->GetNodePtr(i)->GetId() << " "
	    << g->GetNodePtr(i)->GetNodeInfo()->GetCoordX() << " "
	    << g->GetNodePtr(i)->GetNodeInfo()->GetCoordY() << " "
	    << g->GetNodePtr(i)->GetInDegree() << " "
	    << g->GetNodePtr(i)->GetOutDegree() << " ";
    

    switch(g->GetNodePtr(i)->GetNodeInfo()->GetNodeType()) {
    case NodeConf::RT_NODE:
      outfile << ((RouterNodeConf*)(g->GetNodePtr(i)->GetNodeInfo()))->GetASId() << " ";
      
      switch (((RouterNodeConf*)(g->GetNodePtr(i)->GetNodeInfo()))->GetRouterType()) {
      case RouterNodeConf::RT_NONE:
	outfile << "RT_NODE ";
	break;
      case RouterNodeConf::RT_LEAF:
	outfile << "RT_LEAF ";
	break;
      case RouterNodeConf::RT_BORDER:
	outfile << "RT_BORDER";
	break;
      case RouterNodeConf::RT_STUB:
	outfile << "RT_STUB ";
	break;
      case RouterNodeConf::RT_BACKBONE:
	outfile << "RT_BACKBONE ";
	break;
      default:
	cerr << "Topology::Output(): Improperly classfied Router node encountered...\n";
	assert(0);
      }
      break;
      
    case NodeConf::AS_NODE:
      outfile << ((ASNodeConf*)(g->GetNodePtr(i)->GetNodeInfo()))->GetASId() << " ";
      
      switch (((ASNodeConf*)(g->GetNodePtr(i)->GetNodeInfo()))->GetASType()) {
      case ASNodeConf::AS_NONE:
	outfile << "AS_NODE ";
	break;
      case ASNodeConf::AS_LEAF:
	outfile << "AS_LEAF ";
	break;
      case ASNodeConf::AS_STUB:
	outfile << "AS_STUB ";
	break;
      case ASNodeConf::AS_BORDER:
	outfile << "AS_BORDER ";
	break;
      case ASNodeConf::AS_BACKBONE:
	outfile << "AS_BACKBONE ";
	break;
      default:
	cerr << "Topology::Output(): Improperly classfied AS node encountered...\n";
	assert(0);
      }
      break;
    }
    outfile << "\n";
  }

  outfile << "\nEdges: (" << g->GetNumEdges() << "):\n";

  list<Edge*>::iterator el;
  for (el = g->edges.begin(); el != g->edges.end(); el++) {

    outfile << (*el)->GetId() << " "
	    << (*el)->GetSrc()->GetId() << " "
	    << (*el)->GetDst()->GetId() << " "
	    << (*el)->Length() << " ";

    switch((*el)->GetConf()->GetEdgeType()) {
    case EdgeConf::RT_EDGE:
      outfile  << ((RouterEdgeConf*)((*el)->GetConf()))->GetDelay() << " "
	       << (*el)->GetConf()->GetBW() << " "
	//<< (*el)->GetConf()->GetWeight() << " "
	       << ((RouterNodeConf*)((*el)->GetSrc()->GetNodeInfo()))->GetASId() << " "
	       << ((RouterNodeConf*)((*el)->GetDst()->GetNodeInfo()))->GetASId() << " ";
      break;

    case EdgeConf::AS_EDGE:
      outfile  << -1  /* No delay for AS Edges */ << " "
	       << (*el)->GetConf()->GetBW() << " "
	//	       << (*el)->GetConf()->GetWeight() << " "
	       << ((ASNodeConf*)((*el)->GetSrc()->GetNodeInfo()))->GetASId() << " "
	       << ((ASNodeConf*)((*el)->GetDst()->GetNodeInfo()))->GetASId() << " ";
      break;

    default:
      cerr << "Topology::Output(): Invalid Edge type encountered...\n";
      exit(0);
    }
    
    switch ((*el)->GetConf()->GetEdgeType()) {
    case EdgeConf::RT_EDGE: 
      switch (((RouterEdgeConf*)(*el)->GetConf())->GetRouterEdgeType()) {
      case RouterEdgeConf::RT_NONE:
	outfile << "E_RT ";
	break;
      case RouterEdgeConf::RT_STUB:
	outfile << "E_RT_STUB ";
	break;
      case RouterEdgeConf::RT_BORDER:
	outfile << "E_RT_BORDER ";
	break;
      case RouterEdgeConf::RT_BACKBONE:
	outfile << "E_RT_BACKBONE ";
	break;
      default:
	cerr << "Output(): Invalid router edge type...\n";
	assert(0);
      }
      break;

    case EdgeConf::AS_EDGE:

      switch (((ASEdgeConf*)((*el)->GetConf()))->GetASEdgeType()) {
      case ASEdgeConf::AS_NONE:
	outfile << "E_AS ";
	break;
      case ASEdgeConf::AS_STUB:
	outfile << "E_AS_STUB ";
	break;
      case ASEdgeConf::AS_BORDER:
	outfile << "E_AS_BORDER ";
	break;
      case ASEdgeConf::AS_BACKBONE:
	outfile << "E_AS_BACKBONE ";
	break;
      default:
	cerr << "BriteOutput(): Invalid AS edge type...\n";
	assert(0);
      }
      break;
      
    default:
      cerr << "BriteOutput(): Invalid edge type...\n";
      assert(0);
      
    }

    if ((*el)->GetDirection() == true) {
      outfile << "D\n";
    }else {
      outfile << "U\n";
    }
  }
}



    void Topology::OtterOutput(char* filename) {
    
    ofstream outfile;
    string actual_name = filename;
    actual_name += ".odf";
    outfile.open(actual_name.c_str(), ios::out);
    outfile.setf(ios::fixed, ios::floatfield);
    outfile.precision(2);
    assert(outfile);
    
    outfile << "t " << g->GetNumNodes() << "\n";
    outfile << "T " << g->GetNumEdges() << "\n";
    
    for (int i = 0; i < g->GetNumNodes(); i++) {
    
    outfile << "n " << g->GetNodePtr(i)->GetId() << " "
    << (int)g->GetNodePtr(i)->GetNodeInfo()->GetCoordX() << " "
    << (int)g->GetNodePtr(i)->GetNodeInfo()->GetCoordY() << " "
    << g->GetNodePtr(i)->GetOutDegree() << "\n";
    }
    
    list<Edge*>::iterator el;
    for (el = g->edges.begin(); el != g->edges.end(); el++) {
    
    outfile << "l " << (*el)->GetId() << " "
    << (*el)->GetSrc()->GetId() << " "
    << (*el)->GetDst()->GetId() << " \" \"\n";
    }
    
    outfile.close();
    
    }

void Topology::Classify() {

  /* Populate Incidence list */
  list<Edge*>::iterator el;
  for (el = g->edges.begin(); el != g->edges.end(); el++) {
    Edge* edge  = *el;
    g->AddIncListNode(edge);
  }

  /* Look for LEAF nodes */
  for (int i = 0; i < g->GetNumNodes(); i++) {
    
    Node* node = g->GetNodePtr(i);
    assert(node != NULL);

    if (node->GetOutDegree() <= m->GetMEdges()) {

      switch (node->GetNodeInfo()->GetNodeType()) {
      case NodeConf::RT_NODE:
	((RouterNodeConf*)(node->GetNodeInfo()))->SetRouterType(RouterNodeConf::RT_LEAF);
	break;
	
      case NodeConf::AS_NODE:
	((ASNodeConf*)(node->GetNodeInfo()))->SetASType(ASNodeConf::AS_LEAF);
	break;

      default:
	cerr << "Topology.Classify(): Classifying node of unkown type...\n";
	assert(0);
      }
    }
  }

  /* Look for Stub Links */
  for (el = g->edges.begin(); el != g->edges.end(); el++) {
    Node* Src = (*el)->GetSrc();
    Node* Dst = (*el)->GetDst();
    assert(Src != NULL && Dst != NULL);
    if ((Src->GetNodeInfo()->GetNodeType() == NodeConf::RT_NODE &&
	 ((RouterNodeConf*)Src->GetNodeInfo())->GetRouterType() == RouterNodeConf::RT_LEAF) ||
	(Src->GetNodeInfo()->GetNodeType() == NodeConf::AS_NODE &&
	 ((ASNodeConf*)Src->GetNodeInfo())->GetASType() == ASNodeConf::AS_LEAF) ||
	(Dst->GetNodeInfo()->GetNodeType() == NodeConf::RT_NODE &&
	 ((RouterNodeConf*)Dst->GetNodeInfo())->GetRouterType() == RouterNodeConf::RT_LEAF) ||
	(Dst->GetNodeInfo()->GetNodeType() == NodeConf::AS_NODE &&
	 ((ASNodeConf*)Dst->GetNodeInfo())->GetASType() == ASNodeConf::AS_LEAF)) {

      switch((*el)->GetConf()->GetEdgeType()) {
      case EdgeConf::RT_EDGE:
	((RouterEdgeConf*)((*el)->GetConf()))->SetRouterEdgeType(RouterEdgeConf::RT_STUB);
	break;
      case EdgeConf::AS_EDGE:
	((ASEdgeConf*)((*el)->GetConf()))->SetASEdgeType(ASEdgeConf::AS_STUB);
	break;
      }
    }
  }

  /* Look for Stub Routers */
  for (int i = 0; i < g->GetNumNodes(); i++) {

    /* if it has already being classified as a leaf, leaf it alone */
    Node* node = g->GetNodePtr(i);
    if (((node->GetNodeInfo()->GetNodeType() == NodeConf::RT_NODE) && 
	 (((RouterNodeConf*)(node->GetNodeInfo()))->GetRouterType() == RouterNodeConf::RT_LEAF)) ||
	((node->GetNodeInfo()->GetNodeType() == NodeConf::AS_NODE) && 
	 (((ASNodeConf*)(node->GetNodeInfo()))->GetASType() == ASNodeConf::AS_LEAF))) 
      continue;
    
    int num_stub_links = 0;
    for (el = g->incList[i].begin(); el != g->incList[i].end(); el++) {

      if (((((EdgeConf*)((*el)->GetConf()))->GetEdgeType() == EdgeConf::AS_EDGE) &&
	   (((ASEdgeConf*)((*el)->GetConf()))->GetASEdgeType() == ASEdgeConf::AS_STUB)) ||
	  ((((EdgeConf*)((*el)->GetConf()))->GetEdgeType() == EdgeConf::RT_EDGE) &&
	   (((RouterEdgeConf*)((*el)->GetConf()))->GetRouterEdgeType() == RouterEdgeConf::RT_STUB))) {

	num_stub_links += 1;

      }
    }
    
    switch (node->GetNodeInfo()->GetNodeType()) {
    case NodeConf::RT_NODE:
      if (num_stub_links == 1) {
	((RouterNodeConf*)(node->GetNodeInfo()))->SetRouterType(RouterNodeConf::RT_STUB);
      }
      if (num_stub_links > 1) {
	((RouterNodeConf*)(node->GetNodeInfo()))->SetRouterType(RouterNodeConf::RT_BORDER);
      }
      if (num_stub_links == 0) {
	((RouterNodeConf*)(node->GetNodeInfo()))->SetRouterType(RouterNodeConf::RT_BACKBONE);
      }
      break;

    case NodeConf::AS_NODE:
      if (num_stub_links == 1) {
	((ASNodeConf*)(node->GetNodeInfo()))->SetASType(ASNodeConf::AS_STUB);
      }
      if (num_stub_links > 1) {
	((ASNodeConf*)(node->GetNodeInfo()))->SetASType(ASNodeConf::AS_BORDER);
      }
      if (num_stub_links == 0) {
	((ASNodeConf*)(node->GetNodeInfo()))->SetASType(ASNodeConf::AS_BACKBONE);
      }
      break;

    default:
      assert(0);

    }
  }

  /* Final classification of edges: Border and backbone links */
  for (el = g->edges.begin(); el != g->edges.end(); el++) {
    
    Node* Src = (*el)->GetSrc();
    Node* Dst = (*el)->GetDst();
    
    if ((((*el)->GetConf()->GetEdgeType() == EdgeConf::AS_EDGE) &&
	 ((ASEdgeConf*)((*el)->GetConf()))->GetASEdgeType() != ASEdgeConf::AS_STUB) ||
	((*el)->GetConf()->GetEdgeType() == EdgeConf::RT_EDGE) &&
	(((RouterEdgeConf*)((*el)->GetConf()))->GetRouterEdgeType() != RouterEdgeConf::RT_STUB)) {

      
      if (Src->GetNodeInfo()->GetNodeType() == NodeConf::RT_NODE) {
      
	if (((((RouterNodeConf*)(Src->GetNodeInfo()))->GetRouterType() == RouterNodeConf::RT_STUB) &&
	     ((RouterNodeConf*)(Dst->GetNodeInfo()))->GetRouterType() == RouterNodeConf::RT_BORDER) ||
	    ((((RouterNodeConf*)(Src->GetNodeInfo()))->GetRouterType() == RouterNodeConf::RT_BORDER) &&
	     ((RouterNodeConf*)(Dst->GetNodeInfo()))->GetRouterType() == RouterNodeConf::RT_STUB)) {
	  
	  ((RouterEdgeConf*)((*el)->GetConf()))->SetRouterEdgeType(RouterEdgeConf::RT_BORDER);
	  
	}else {
	  
	  ((RouterEdgeConf*)((*el)->GetConf()))->SetRouterEdgeType(RouterEdgeConf::RT_BACKBONE);

	}

      }else {

	if (((((ASNodeConf*)(Src->GetNodeInfo()))->GetASType() == ASNodeConf::AS_STUB) &&
	     ((ASNodeConf*)(Dst->GetNodeInfo()))->GetASType() == ASNodeConf::AS_BORDER) ||
	    ((((ASNodeConf*)(Src->GetNodeInfo()))->GetASType() == ASNodeConf::AS_BORDER) &&
	     ((ASNodeConf*)(Dst->GetNodeInfo()))->GetASType() == ASNodeConf::AS_STUB)) {
	  
	  ((ASEdgeConf*)((*el)->GetConf()))->SetASEdgeType(ASEdgeConf::AS_BORDER);

	}else {
	  
	  ((ASEdgeConf*)((*el)->GetConf()))->SetASEdgeType(ASEdgeConf::AS_BACKBONE);

	}
      }
    }
  }
}

