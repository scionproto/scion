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
#pragma implementation "BottomUpHierModel.h"

#include "BottomUpHierModel.h"
#include "RouterWaxmanModel.h"
#include "RouterBarabasiAlbertModel-1.h"
#include "ASWaxmanModel.h"
#include "ASBarabasiAlbertModel.h"
#include "ImportedFileModel.h"

BottomUpHierModel::BottomUpHierModel(BottUpPar* par) : models(2) {

  RouterWaxman* rt_wax_model;
  RouterBarabasiAlbert_1* rt_bar_model;
  ImportedBriteTopologyModel* if_brite_model;
  ImportedGTitmTopologyModel* if_gtitm_model;  
  ImportedNLANRTopologyModel* if_nlanr_model;

  nlevels = 2;
  ASNodes = par->GetASNodes();
  group = (GroupingType)par->GetGM();
  at = (AssignmentType)par->GetAT();
  m_edges = par->GetM();
  type = BU_HIER;
  BWInterdist = (BWDistType)(par->GetBWInter());
  BWIntermin = par->GetBWInterMin();
  BWIntermax = par->GetBWInterMax();

  switch (par->GetModelPar(0)->GetModelType()) {
  case RT_WAXMAN:
    rt_wax_model = new RouterWaxman((RouterWaxPar*)(par->GetModelPar(0)));
    models[0] = rt_wax_model;
    break;

  case RT_BARABASI_1:
    rt_bar_model = new RouterBarabasiAlbert_1((RouterBarabasiAlbert_1_Par*)(par->GetModelPar(0)));
    models[0] = rt_bar_model;
    break;

  case IF_ROUTER:
  case IF_AS:
    switch (((ImportedFilePar*)par->GetModelPar(0))->GetFormat()) {
    case ImportedFileModel::IF_BRITE:
      cout << "BU: Importing brite...\n" << flush;
      if_brite_model = new ImportedBriteTopologyModel((ImportedFilePar*)par->GetModelPar(0));
      models[0] = if_brite_model;
      break;

    case ImportedFileModel::IF_GTITM:
    case ImportedFileModel::IF_GTITM_TS:
      cout << "BU: Importing gtitm...\n" << flush;
      if_gtitm_model = new ImportedGTitmTopologyModel((ImportedFilePar*)par->GetModelPar(0));
      models[0] = if_gtitm_model;
      break;

    case ImportedFileModel::IF_NLANR:
      cout << "BU: Importing nlanr..\n" << flush;
      if_nlanr_model = new ImportedNLANRTopologyModel((ImportedFilePar*)par->GetModelPar(0));
      models[0] = if_nlanr_model;
      break;
      
    case ImportedFileModel::IF_SKITTER:
      cerr << "BU: Skitter model will be available soon...\n" << flush;
      exit(0);
      
    default:
      cerr << "BottomUpHierModel(): Invalid file format for ImportedFileModel...\n" << flush;
      exit(0);
    }
    break;

  default:
    cerr << "Invalid model type for BU model...\n" << flush;
    assert(0);
  }
}

string BottomUpHierModel::ToString() {
  
    //  char buf[200];
    //  ostrstream os((char*)buf, 200);
    //  string s;

  ostringstream os(ostringstream::out);

  os << "Model ( 6 ): " 
     << ASNodes << " "
     << (int)group << " "
     << (int)at << " "
     << (int)BWInterdist << " "
     << BWIntermin << " "
     << BWIntermax << "\n";

  os << "Router Level: ";
  switch (models[0]->GetType()) {
  case RT_WAXMAN:
    os  << ((RouterWaxman*)models[0])->ToString() << '\0';
    break;
  case RT_BARABASI_1:
    os  << ((RouterBarabasiAlbert_1*)models[0])->ToString()  << '\0';
    break;
  case IF_ROUTER:
  case IF_AS:
    os  << ((ImportedFileModel*)models[0])->ToString()  << '\0';
    break;

  default:
    cerr << "BottomUpHierModel::ToString(): Invalid Router model type...\n" << flush;
    exit(0);

  }

  return string(os.str());

}

Graph* BottomUpHierModel::Generate() {

    cout << "Generating Botton up hierarchical topology...\n" << flush;

    /* Generate topology according to router-level model */
    Graph* graph = models[0]->Generate();

    /* "generate" AS level topology by grouping routers into ASes */
    cout << "Grouping nodes...\n" << flush;
    GroupNodes(graph);

    /* Assigning BW for Inter-domain links */
    cout << "Assigning bandwidth...\n" << flush;
    AssignBW(graph);

    return graph;

}


void BottomUpHierModel::GroupNodes(Graph* g) {
    
  int i, j, size, n, assigned;
  int start, count, total_assigned = 0;
  Node* Src;
  RandomVariable G(Model::s_grouping);
  RandomVariable A(Model::s_assignment);
  
  vector<Color> color(g->GetNumNodes());
  for (int i = 0; i < g->GetNumNodes(); i++) {
    color[i] = WHITE;
  }

  total_assigned = 0;
  i = 0;
  start = 0;
  while (total_assigned < g->GetNumNodes()) {

    assigned = 0;
    switch (at) {
    case A_CONST:
      size = g->GetNumNodes()/ASNodes;
      break;
      
    case A_UNIF:
      size = (int)A.GetValUniform(1.0, g->GetNumNodes());
      break;

    case A_EXP:
      size = (int)A.GetValExponential((double)ASNodes/g->GetNumNodes());
      break;
      
    case A_HT:
      size = (int)A.GetValPareto(g->GetNumNodes(), 1.2);
      break;
      
    default:
      cerr << "GroupNodes(): Invalid Assignment model...\n" << flush;
      exit(0);
    }
    
    switch (group) {
    case BU_RANDOM_PICK:	

      j = 0;
      while (j < size && total_assigned < g->GetNumNodes()) {
	n = (int)floor(G.GetValUniform(g->GetNumNodes()));
	Src = g->GetNodePtr(n);
	if (((RouterNodeConf*)Src->GetNodeInfo())->GetASId() == -1) {
	  ((RouterNodeConf*)Src->GetNodeInfo())->SetASId(i);
	  j += 1;
	  assigned += 1;
	  total_assigned += 1;
	  if (assigned == g->GetNumNodes()) return;
	}
      }
      i += 1;
      cout << "Ass: " << size << " got: " << j << "\n" << flush;
      break;
	
    case BU_RANDOM_WALK:  
      
      j = 0;
      count = 0;
      for (int s = 0; i < g->GetNumNodes(); s++) {
	if (color[s] != BLACK) {
	  start = s;
	  break;
	}
      }

      count = 0;
      RandomWalk(g, color, start, size, G, i, count);
      cout << "i: " << i << " Ass  " << size << " got: " << count << "\n" << flush;
      if (count > 0) {
	assigned += count;
	total_assigned += assigned;
	if (assigned == g->GetNumNodes()) return;
	i += 1;
      }
      break;

    default:
      cerr << "Invalid grouping method for Bottom-up hierarchical model...\n" << flush;
      exit(0);
    }


  
  }

  cout << "Actual Number of ASes: " << i << "\n" << flush;

}

void BottomUpHierModel::RandomWalk(Graph* g, vector<Color>& color, int u, 
				  int size, RandomVariable& U, int AS, int& c) {

  int v, l;
  int neighbors = g->GetAdjListSize(u);

  /* Assign this node */
  if (color[u] == WHITE) {

    ((RouterNodeConf*)g->GetNodePtr(u)->GetNodeInfo())->SetASId(AS);
    color[u] = GRAY;
    c++;

  }

  while (c < size) {

    /* Check for Available neighbors */
    list<int>::iterator al;
    l = 0;  
    for (al = g->adjList[u].begin(); al != g->adjList[u].end(); al++) {
      if (color[*al] == WHITE) {
	l = 1;
	break;
      }
    }
    
    /* No available neighbors */
    if (l == 0) {
      color[u] = BLACK;
      return;
    }

    /* Pick random neighbor */
    l = 0;
    while (!l) {

      int n = (int)floor(U.GetValUniform(neighbors + 1));
      int j = 0;
      for (al = g->adjList[u].begin(); al != g->adjList[u].end(); al++) {
	j++;
	if (j == n) break;
      }
      v = *al;

      if (color[v] != WHITE) continue;
      l = 1;
    }

    RandomWalk(g, color, v, size, U, AS, c);
    
  }
}
 

void BottomUpHierModel::AssignBW(Graph* g) {

  RandomVariable BW(s_bandwidth);

  /* Traverse edge list: for each edge with ASFrom != ASTo assign
   * a BW from Inter-domain BW distribution */
  list<Edge*>::iterator el;
  for (el = g->edges.begin(); el != g->edges.end(); el++) {
      
    assert((*el)->GetSrc()->GetNodeInfo()->GetNodeType() == NodeConf::RT_NODE);
    assert((*el)->GetDst()->GetNodeInfo()->GetNodeType() == NodeConf::RT_NODE);
    int ASFrom = (*el)->GetSrc()->GetId();
    int ASTo = (*el)->GetDst()->GetId();
    
    if (ASFrom != ASTo) {
      switch (GetBWInterDist()) {
      case BW_CONST:
	(*el)->GetConf()->SetBW(BWIntermin);
	break;
	
      case BW_UNIF:
	(*el)->GetConf()->SetBW(BW.GetValUniform(BWIntermin, BWIntermax));
	break;
	
      case BW_EXP:
	(*el)->GetConf()->SetBW(BW.GetValExponential(1.0/BWIntermin));
	break;

      case BW_HT:
	(*el)->GetConf()->SetBW(BW.GetValPareto(BWIntermax, 1.2));
	break;

      default:
	cerr << "BUHier::AssignBW():  invalid BW distribution (" 
	     << GetBWInterDist() << ")...\n" << flush;
	exit(0);
      }
    }
  }
}

