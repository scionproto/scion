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
#pragma implementation "ImportedFileModel.h"

#include "ImportedFileModel.h"

ImportedFileModel::ImportedFileModel(ImportedFilePar* par) : model_strings(3) {

  format = (ImportedFileFormat)par->GetFormat();
  filename = par->GetFileName();
  Scale_1 = par->GetHS();
  Scale_2 = par->GetLS();
  assert(Scale_2 > 0 && Scale_1 > Scale_2);

  switch (par->GetModelType()) {
  case 7:
    level = RT_LEVEL;
    type = IF_ROUTER;
    break;
  case 8:
  case 9:
    level = AS_LEVEL;
    type = IF_AS;
    break;
  default:
    cerr << "ImportedFileModel(): Invalid level for IF topology...\n" << flush;
    exit(0);
  }
  assert(par->GetBW() == BW_CONST ||
	 par->GetBW() == BW_UNIF ||
	 par->GetBW() == BW_EXP ||
	 par->GetBW() == BW_HT);
  SetBWDist((BWDistType)par->GetBW());
  SetBWMin(par->GetBWMin());
  SetBWMax(par->GetBWMax());

}

ImportedBriteTopologyModel::ImportedBriteTopologyModel(ImportedFilePar* par)
  :  ImportedFileModel(par) {}

ImportedGTitmTopologyModel::ImportedGTitmTopologyModel(ImportedFilePar* par)
  : ImportedFileModel(par) {}

ImportedNLANRTopologyModel::ImportedNLANRTopologyModel(ImportedFilePar* par)
  : ImportedFileModel(par), U(s_places) {}

ImportedInetTopologyModel::ImportedInetTopologyModel(ImportedFilePar* par)
  : ImportedFileModel(par) {}

ImportedSkitterTopologyModel::ImportedSkitterTopologyModel(ImportedFilePar* par)
  : ImportedFileModel(par) {}


void ImportedFileModel::AssignBW(Graph* g) {

  double v;
  RandomVariable BW(s_bandwidth);

  list<Edge*>::iterator el;
  for (el = g->edges.begin(); el != g->edges.end(); el++) {

    switch (BWdist) {
    case BW_CONST:
      v = BWmin;
      break;
      
    case BW_UNIF:
      v =  BW.GetValUniform(BWmin, BWmax);
      break;
      
    case BW_EXP:    
      v = BW.GetValExponential(1.0/BWmin);
      break;
      
    case BW_HT:
      v = BW.GetValPareto(BWmax, 1.2);
      break;
      
    default:
      cerr << "ImportedFileModel::AssignBW():  invalid BW distribution (" 
	   << (int)BWdist << ")...\n" << flush;
    }

    (*el)->GetConf()->SetBW(v);

  }

}



string ImportedFileModel::ToString() {
  
    //  char buf[200];
    //  ostrstream os((char*)buf, 200);
    //  string s;

  ostringstream os(ostringstream::out);

  os << "Model ( ";
  switch (level) {
  case RT_LEVEL:
    os << 7 << " )";
    break;

  case AS_LEVEL:
    os << 8 << " )";
    break;

  default:
    cerr << "ImportedFileModel(): Invalid level for IF topology...\n" << flush;
    exit(0);
  }
  os << " " <<  (int)format << " "
     << filename << " "
     << (int)GetBWDist() << " "
     << GetBWMin() << " "
     << GetBWMax() << "\n" << '\0';
    
  string r = os.str();
  for (int i = 0; i < num_strings; i++) {
    r += "Imported model: " + model_strings[i] + "\n";
  }

  os << '\0';

  return (r);

}

Graph* ImportedBriteTopologyModel::Generate() {

  Graph* graph;

  cout << "Importing a BRITE topology...\n" << flush;
  graph = ParseFile();

  return graph;

}

Graph* ImportedGTitmTopologyModel::Generate() {

  Graph* graph;

  graph = ParseFile();

  /* Assign bandwidths to edges */
  AssignBW(graph);
    
  return graph;

}

Graph* ImportedNLANRTopologyModel::Generate() {

  Graph* graph;
    
  graph = ParseFile();

  /* Assign bandwidths to edges */
  AssignBW(graph);

  return graph;

}

Graph* ImportedInetTopologyModel::Generate() {

  Graph* graph;

  cout << "Importing an Inet topology...\n" << flush;
  graph = ParseFile();

  /* Assign bandwidths to edges */
  AssignBW(graph);

  return graph;

}


Graph* ImportedSkitterTopologyModel::Generate() {

  Graph* graph;
  
  cerr << "Skitter Topology: will be available soon...\n" << flush;
  exit(0);
  
  return graph;
  
}


Graph* ImportedBriteTopologyModel::ParseFile() {

  int i;

  /* Keep information about topology read */
  string model_string;

  /* Initialize vector of tokens */
  vector<string> toks(MAXLINE);

  /* Open file for parsing */
  Parse p((char*)filename.c_str());

  /* Parse headers */
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (toks[0] != "Topology:") p.ParseError("Topology:", toks[0]);
  if (toks[1] != "(") p.ParseError("(", toks[1]);
  int nodes = atoi(toks[2].c_str());
  assert(nodes > 0);
  if (toks[3] != "Nodes,") p.ParseError("Nodes,", toks[3]);
  int edges = atoi(toks[4].c_str());
  assert(edges > 0);
  if (toks[5] != "Edges") p.ParseError("Edges", toks[5]);
  if (toks[6] != ")") p.ParseError(")", toks[6]);
  
  /* Parse Model information */
  toks[0] = "";
  model_string = "";
  while (toks[0] != "Nodes:") {
    
    while ((i = p.GetNextTokenList(toks)) == 0);
    if (i < 0) p.ParseError("Model information", "EOF");
    if (toks[0] != "Nodes:") {
      for (int j = 0; j < i; j++) {
	model_string += toks[i] + " ";
      }
      model_string += "\n";
    }
  }
  num_strings = 1;

  Graph* graph = new Graph(nodes);

  for (int j = 0; j < nodes; j++) {

    while ((i = p.GetNextTokenList(toks)) == 0);
    if (i < 0) p.ParseError("Node lines", "EOF");
    int nid = atoi(toks[0].c_str()); 
    double x = atof(toks[1].c_str()); 
    double y = atof(toks[2].c_str());
    /*    int ideg = atoi(toks[3].c_str()); 
	  int odeg = atoi(toks[4].c_str()); */
    int asid = atoi(toks[5].c_str()); 
    string type = toks[6];

    try {

      /* Add node to Graph */
      Node* node = new Node(j);
      graph->AddNode(node, j);
      node->SetId(nid);
      /*      node->SetInDegree(ideg);
	      node->SetOutDegree(odeg);*/
      node->SetInDegree(0);
      node->SetOutDegree(0);

      RouterNodeConf* n_rt_conf;
      ASNodeConf* n_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	/* Set information specific to router nodes */
	n_rt_conf = new RouterNodeConf();
	n_rt_conf->SetCoord(x, y, 0.0); 
	n_rt_conf->SetNodeType(NodeConf::RT_NODE);
	if (type == "RT_BACKBONE") n_rt_conf->SetRouterType(RouterNodeConf::RT_BACKBONE);
	else if (type == "RT_NONE") n_rt_conf->SetRouterType(RouterNodeConf::RT_NONE);
	else if (type == "RT_BORDER") n_rt_conf->SetRouterType(RouterNodeConf::RT_BORDER);
	else if (type == "RT_STUB") n_rt_conf->SetRouterType(RouterNodeConf::RT_STUB);
	else if (type == "RT_LEAF") n_rt_conf->SetRouterType(RouterNodeConf::RT_LEAF);
	else { 
	  cerr << "ImportBriteTopology(): Invalid Router node type (" 
	       << type << ") " << nid << "  read...\n" << flush; 
	  exit(0); 
	}
	n_rt_conf->SetASId(asid);
	node->SetNodeInfo(n_rt_conf);
	break;
	
      case ImportedFileModel::AS_LEVEL:

	/* Set information specific to AS nodes */
	n_as_conf = new ASNodeConf();
	n_as_conf->SetCoord(x, y, 0.0); 
	n_as_conf->SetNodeType(NodeConf::AS_NODE);
	if (type == "AS_BACKBONE") n_as_conf->SetASType(ASNodeConf::AS_BACKBONE);
	else if (type == "AS_BORDER") n_as_conf->SetASType(ASNodeConf::AS_BORDER);
	else if (type == "AS_NONE") n_as_conf->SetASType(ASNodeConf::AS_NONE);
	else if (type == "AS_STUB") n_as_conf->SetASType(ASNodeConf::AS_STUB);
	else if (type == "AS_LEAF") n_as_conf->SetASType(ASNodeConf::AS_LEAF);
	else { cerr << "ImportBriteTopology(): Invalid AS node type read...\n" << flush; exit(0); }
	n_as_conf->SetASId(j);
	n_as_conf->SetTopology(NULL, 0);
	node->SetNodeInfo(n_as_conf);
	break;

      default:
	cerr << "ImportBriteTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);

      }
    }
    catch (bad_alloc) {
      cerr << "ImportBriteTopology(): Cannot allocate new node...\n" << flush;
      exit(0);
    }
  }

  /* Parse Edges */
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (i < 0) p.ParseError("Edges", "EOF");			 
  if (toks[0] != "Edges:") p.ParseError("Edges:", toks[0]);  
  
  for (int j = 0; j < edges; j++) {
    
    while ((i = p.GetNextTokenList(toks)) == 0);
    if (i < 0) p.ParseError("Edge information", "EOF");			 
    
    int nfrom = atoi(toks[1].c_str());
    int nto = atoi(toks[2].c_str());
    double len = atof(toks[3].c_str());
    double delay = atof(toks[4].c_str());
    double bw = atof(toks[5].c_str());
    double weight = atof(toks[6].c_str());
    string type = toks[9];
    string direction = toks[10];

    try {

      /* Add new edge to graph */
      Edge* edge = new Edge(graph->GetNodePtr(nfrom), graph->GetNodePtr(nto));
      graph->AddEdge(edge);

      Node* from = graph->GetNodePtr(nfrom);
      Node* to = graph->GetNodePtr(nto);

      RouterEdgeConf* e_rt_conf;
      ASEdgeConf* e_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	e_rt_conf = new RouterEdgeConf(len);
	e_rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	e_rt_conf->SetWeight(weight);
	e_rt_conf->SetBW(bw);
	e_rt_conf->SetLength(len);
	e_rt_conf->SetDelay(delay);
	if (type == "E_RT_BACKBONE") e_rt_conf->SetRouterEdgeType(RouterEdgeConf::RT_BACKBONE);
	else if (type == "E_RT_BORDER") e_rt_conf->SetRouterEdgeType(RouterEdgeConf::RT_BORDER);
	else if (type == "E_RT_STUB") e_rt_conf->SetRouterEdgeType(RouterEdgeConf::RT_STUB);
	else if (type == "E_RT_NONE") e_rt_conf->SetRouterEdgeType(RouterEdgeConf::RT_NONE);
	else { cerr << "ImportBriteTopology(): Invalid Router edge type read...\n" << flush; exit(0); }
	edge->SetConf(e_rt_conf);
	break;

      case ImportedFileModel::AS_LEVEL:

	e_as_conf = new ASEdgeConf();
	e_as_conf->SetEdgeType(EdgeConf::AS_EDGE);
	e_as_conf->SetWeight(weight);
	e_as_conf->SetBW(bw);

	if (type == "E_AS_BACKBONE") e_as_conf->SetASEdgeType(ASEdgeConf::AS_BACKBONE);
	else if (type == "E_AS_BORDER") e_as_conf->SetASEdgeType(ASEdgeConf::AS_BORDER);
	else if (type == "E_AS_STUB") e_as_conf->SetASEdgeType(ASEdgeConf::AS_STUB);
	else if (type == "E_AS_NONE") e_as_conf->SetASEdgeType(ASEdgeConf::AS_NONE);
	else { cerr << "ImportBriteTopology(): Invalid AS edge type read...\n" << flush; exit(0); }
	edge->SetConf(e_as_conf);
	break;

      default:
	cerr << "ImportBriteTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);
      }
      /* Update adjacency lists */
      if (direction == "D") {

	edge->SetDirection(true);
	graph->AddAdjListNode(nfrom, nto);

	from->SetOutDegree(from->GetOutDegree() + 1);
	to->SetInDegree(to->GetInDegree() + 1);

      }else {

	edge->SetDirection(false);
	graph->AddAdjListNode(nfrom, nto);
	graph->AddAdjListNode(nto, nfrom);

	from->SetOutDegree(from->GetOutDegree() + 1);
	from->SetInDegree(from->GetInDegree() + 1);
	to->SetOutDegree(to->GetOutDegree() + 1);
	to->SetInDegree(to->GetInDegree() + 1);
	
      }

    }
    catch (bad_alloc) {
      cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
      exit(0);
    }

  }

  return graph;
  
}


Graph* ImportedGTitmTopologyModel::ParseFile() {

  Graph* graph;

  switch (format) {
  case IF_GTITM:
    graph = ParseFlatGTITM();
    break;

  case IF_GTITM_TS:
    graph = ParseTSGTITM();
    break;

  default:
    cerr << "ImportedGTitmFileModel():  Invalid format...\n" << flush;
    exit(0);

  }

  return graph;
}


Graph* ImportedGTitmTopologyModel::ParseFlatGTITM() {

  int i;

  /* Initialize vector of tokens */
  vector<string> toks(MAXLINE);

  /* Open file for parsing */
  Parse p((char*)filename.c_str());

  /* Parse headers */
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (toks[0] != "GRAPH") p.ParseError("GRAPH", toks[0]);
  if (toks[1] != "(#nodes") p.ParseError("(#nodes", toks[1]);

  while ((i = p.GetNextTokenList(toks)) == 0);
  int nodes = atoi(toks[0].c_str());
  assert(nodes > 0);
  int edges = atoi(toks[1].c_str());
  assert(edges > 0);
  
  string model_string = "";
  for (int j = 0; j < i; j++) {
    model_string += " " + toks[j];
  }
  num_strings = 1;
  model_strings[0] = model_string + "\0";

  Graph* graph = new Graph(nodes);

  cout << "Parsing nodes...\n" << flush;
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (toks[0] != "VERTICES") p.ParseError("VERTICES", toks[0]);
  
  for (int j = 0; j < nodes; j++) {
    
    while ((i = p.GetNextTokenList(toks)) == 0);
    int nid = atoi(toks[0].c_str()); 
    double x = atof(toks[2].c_str()); 
    double y = atof(toks[3].c_str());

    try {

      /* Add node to Graph */
      Node* node = new Node(j);
      graph->AddNode(node, j);
      assert(j == nid);
      node->SetInDegree(0);
      node->SetOutDegree(0);

      RouterNodeConf* n_rt_conf;
      ASNodeConf* n_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	/* Set information specific to router nodes */
	n_rt_conf = new RouterNodeConf();
	n_rt_conf->SetCoord(x, y, 0.0); 
	n_rt_conf->SetNodeType(NodeConf::RT_NODE);
	n_rt_conf->SetRouterType(RouterNodeConf::RT_NONE);
	n_rt_conf->SetASId(0);
	node->SetNodeInfo(n_rt_conf);
	break;
	
      case ImportedFileModel::AS_LEVEL:

	/* Set information specific to AS nodes */
	n_as_conf = new ASNodeConf();
	n_as_conf->SetCoord(x, y, 0.0); 
	n_as_conf->SetNodeType(NodeConf::AS_NODE);
	n_as_conf->SetASType(ASNodeConf::AS_NONE);
	n_as_conf->SetASId(j);
	n_as_conf->SetTopology(NULL, 0);
	node->SetNodeInfo(n_as_conf);
	break;

      default:
	cerr << "ImportGTitmTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);

      }
    }
    catch (bad_alloc) {
      cerr << "ImportGTitmTopology(): Cannot allocate new node...\n" << flush;
      exit(0);
    }
  }

  /* Parse Edges */
  cout << "Parsing edges...\n" << flush;
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (toks[0] != "EDGES") p.ParseError("EDGES", toks[0]);  
  
  int num_edges = 0;
  while ((i = p.GetNextTokenList(toks)) > 0) {

    int nfrom = atoi(toks[0].c_str());
    int nto = atoi(toks[1].c_str());

    try {

      /* Add new edge to graph */
      Node* Src = graph->GetNodePtr(nfrom);
      Node* Dst = graph->GetNodePtr(nto);
      Edge* edge = new Edge(Src, Dst );
      graph->AddEdge(edge);

      RouterEdgeConf* e_rt_conf;
      ASEdgeConf* e_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	e_rt_conf = new RouterEdgeConf(edge->Length());
	e_rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	e_rt_conf->SetBW(0.0);
	edge->SetConf(e_rt_conf);
	break;

      case ImportedFileModel::AS_LEVEL:

	e_as_conf = new ASEdgeConf();
	e_as_conf->SetEdgeType(EdgeConf::RT_EDGE);
	e_as_conf->SetBW(0.0);
	edge->SetConf(e_as_conf);
	break;

      default:
	cerr << "ImporGTITMTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);
      }
      /* Update adjacency lists */
      graph->AddAdjListNode(nfrom, nto);
      graph->AddAdjListNode(nto, nfrom);
      
      Src->SetInDegree(Src->GetInDegree() + 1);
      Dst->SetInDegree(Dst->GetInDegree() + 1);
      Src->SetOutDegree(Src->GetOutDegree() + 1);
      Dst->SetOutDegree(Dst->GetOutDegree() + 1);
      num_edges += 2;

    }
    catch (bad_alloc) {
      cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
      exit(0);
    }
    
  }
  
  assert(num_edges == edges);

  return graph;
  
}

Graph* ImportedGTitmTopologyModel::ParseTSGTITM() {

  int i;

  /* Initialize vector of tokens */
  vector<string> toks(MAXLINE);

  /* Open file for parsing */
  Parse p((char*)filename.c_str());

  /* Parse headers */
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (toks[0] != "GRAPH") p.ParseError("GRAPH", toks[0]);
  if (toks[1] != "(#nodes") p.ParseError("(#nodes", toks[1]);

  while ((i = p.GetNextTokenList(toks)) == 0);
  int nodes = atoi(toks[0].c_str());
  assert(nodes > 0);
  int edges = atoi(toks[1].c_str());
  assert(edges > 0);
  if (toks[2].compare(string("transtub", 0, 8)) != 0) 
    p.ParseError("n m transtub(...", toks[2]);

  string model_string = "";
  for (int j = 0; j < i; j++) {
    model_string += " " + toks[j];
  }
  num_strings = 1;
  model_strings[0] = model_string + "\0";
  Graph* graph = new Graph(nodes);

  cout << "Parsing nodes...\n" << flush;
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (toks[0] != "VERTICES") p.ParseError("VERTICES", toks[0]);
  
  int lastASid = -1;
  int TASMark = -1;
  int SMark1 = -1, SMark2 = -1;

  for (int j = 0; j < nodes; j++) {
    
    int pos = 0;

    /* Get next line of tokens from file */
    while ((i = p.GetNextTokenList(toks)) == 0);

    int nid = atoi(toks[0].c_str()); 
    string address = toks[1];
    double x = atof(toks[2].c_str()); 
    double y = atof(toks[3].c_str());
    int asid;

    /* Determine AS id from address token */
    switch (address[0]) {
    case 'T':
      address = toks[1];
      i = p.GetNextTokenList(address, pos, toks);

      if (atoi(toks[0].c_str()) == TASMark) {
	asid = lastASid;
      }else {
	TASMark = atoi(toks[0].c_str());
	lastASid += 1;
	asid = lastASid;
      }
      break;

    case 'S':

      address = toks[1];
      i = p.GetNextTokenList(address, pos, toks);
      if ((atoi(toks[2].c_str()) == SMark1) && (atoi(toks[3].c_str()) == SMark2)) {
	asid = lastASid;
      }else {
	SMark1 = atoi(toks[2].c_str());	
	SMark2 = atoi(toks[3].c_str());
	lastASid += 1;
	asid = lastASid;
      }
      break;

    default:
      cerr << "Unknown node: " << toks[1] << "\n" << flush;
      exit(0);
    }

    try {

      /* Add node to Graph */
      Node* node = new Node(j);
      graph->AddNode(node, j);
      assert(j == nid);
      node->SetInDegree(0);
      node->SetOutDegree(0);

      RouterNodeConf* n_rt_conf;
      ASNodeConf* n_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	/* Set information specific to router nodes */
	n_rt_conf = new RouterNodeConf();
	n_rt_conf->SetCoord(x, y, 0.0); 
	n_rt_conf->SetASId(asid);
	node->SetNodeInfo(n_rt_conf);
	break;
	
      case ImportedFileModel::AS_LEVEL:

	/* Set information specific to AS nodes */
	n_as_conf = new ASNodeConf();
	n_as_conf->SetCoord(x, y, 0.0); 
	n_as_conf->SetASId(asid);
	n_as_conf->SetTopology(NULL, 0);
	node->SetNodeInfo(n_as_conf);
	break;

      default:
	cerr << "ImportGTitmTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);

      }
    }
    catch (bad_alloc) {
      cerr << "ImportGTitmTopology(): Cannot allocate new node...\n" << flush;
      exit(0);
    }    

  }
  cout << "Number of ASes assigned: " << lastASid + 1 << "\n" << flush;

  /* Parse Edges */
  cout << "Parsing edges...\n" << flush;
  while ((i = p.GetNextTokenList(toks)) == 0);
  if (toks[0] != "EDGES") p.ParseError("EDGES", toks[0]);  
  int num_edges = 0;
  while ((i = p.GetNextTokenList(toks)) > 0) {

    int nfrom = atoi(toks[0].c_str());
    int nto = atoi(toks[1].c_str());

    try {

      /* Add new edge to graph */
      Node* Src = graph->GetNodePtr(nfrom);
      Node* Dst = graph->GetNodePtr(nto);
      Edge* edge = new Edge(Src, Dst );
      graph->AddEdge(edge);

      RouterEdgeConf* e_rt_conf;
      ASEdgeConf* e_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	e_rt_conf = new RouterEdgeConf(edge->Length());
	e_rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	e_rt_conf->SetBW(0.0);
	edge->SetConf(e_rt_conf);
	break;

      case ImportedFileModel::AS_LEVEL:

	e_as_conf = new ASEdgeConf();
	e_as_conf->SetEdgeType(EdgeConf::RT_EDGE);
	e_as_conf->SetBW(0.0);
	edge->SetConf(e_as_conf);
	break;

      default:
	cerr << "ImporGTITMTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);
      }
      /* Update adjacency lists */
      graph->AddAdjListNode(nfrom, nto);
      graph->AddAdjListNode(nto, nfrom);
      
      Src->SetInDegree(Src->GetInDegree() + 1);
      Dst->SetInDegree(Dst->GetInDegree() + 1);
      Src->SetOutDegree(Src->GetOutDegree() + 1);
      Dst->SetOutDegree(Dst->GetOutDegree() + 1);
      num_edges += 2;

    }
    catch (bad_alloc) {
      cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
      exit(0);
    }
    
  }
  cout << "EDGES to be PARSED: " << edges << " edges parsed: " << num_edges << "\n" << flush;
  //  assert(num_edges == edges);

  return graph;
  
}


Graph* ImportedNLANRTopologyModel::ParseFile() {

  Graph* graph;
  int repeated = 0;
  
  /* Open file for parsing */
  Parse p((char*)filename.c_str());

  int nodes = p.FileSize();

  try {
    graph = new Graph(nodes);
  }
  catch (bad_alloc) {
    cerr << "ImportNLANRTopology(): Cannot create new graph...\n" << flush;
    exit(0);
  }

  int i, degree, nid = 0, nidsrc, niddst;
  string node_string, neighbor_string;
  vector<string> toks(4);
  vector<string> auxid(nodes);

  /* Parse Nodes */
  cout << "Parsing nodes...\n" << flush;
  while ((i = p.GetNextTokenList(toks)) > 0) { 
    
    if ((i == 0) || (toks[1] != "->")) p.ParseError("->", toks[1]);
    auxid[nid] =  toks[0];
    PlaceNode(graph, nid, toks[0]);
    nid += 1;    
    
  }

  /* Set file get-pointer back to beginning */
  p.ResetFilePointer();
  
  /* Parse edges */
  cout << "Parsing edges...\n" << flush;
  while ((i = p.GetNextToken(node_string)) != 0) { 

    for (int j = 0; j < nodes; j++) {
      if (auxid[j] == node_string)  {
	nidsrc = j;
	break;
      }
    }

    p.ParseStringField("->");
    p.ParseIntField(degree);

    for (int j = 0; j < degree; j++) {
      i = p.GetNextToken(neighbor_string);
      if (i == 0) p.ParseError("int node id", neighbor_string);
      for (int k = 0; k < nodes; k++) {
	if (auxid[k] == neighbor_string)  {
	  niddst = k;
	  break;
	}
      }

      /* Check for repeated edges in NLANR file */
      if (graph->AdjListFind(nidsrc, niddst)) {
	repeated++;
	continue;
      }
      

      PlaceEdge(graph, nidsrc, niddst);

    }
  }
  
  if (repeated > 0 ) {
    cout << "*** ImportNLANRTopology() - Warning!: \n"  
	 << "*** " << repeated << " repeated edges found \n"
	 << "*** Repeated edges were not added...\n" << flush;
  }
  return graph;
  
}


void ImportedNLANRTopologyModel::PlaceNode(Graph* g, int nid, string auxid) {

  double x, y, z;
  bool found = true;

  while (found) {
    
    x = floor(U.GetValUniform((double) Scale_1));
    y = floor(U.GetValUniform((double) Scale_1));
    z = 0.0; 
    /* Check for Placement Collision */       
    int tx = (int)x;
    int ty = (int)y;
    
    found = PlaneCollision(tx, ty);
    
  }

  /* Add node to Graph */
  Node* node = new Node(nid);
  g->AddNode(node, nid);
  
  RouterNodeConf* n_rt_conf;
  ASNodeConf* n_as_conf;
  
  switch (level) {
  case ImportedFileModel::RT_LEVEL:
    
    /* Set information specific to router nodes */
    n_rt_conf = new RouterNodeConf();
    n_rt_conf->SetCoord(x, y, 0.0); 
    n_rt_conf->SetNodeType(NodeConf::RT_NODE);
    n_rt_conf->SetRouterType(RouterNodeConf::RT_NONE);
    n_rt_conf->SetASId(0);
    node->SetNodeInfo(n_rt_conf);
    break;
    
  case ImportedFileModel::AS_LEVEL:
    
    /* Set information specific to AS nodes */
    n_as_conf = new ASNodeConf();
    n_as_conf->SetCoord(x, y, 0.0); 
    n_as_conf->SetNodeType(NodeConf::AS_NODE);
    n_as_conf->SetASType(ASNodeConf::AS_NONE);
    n_as_conf->SetASId(atoi(auxid.c_str()));
    n_as_conf->SetTopology(NULL, 0);
    node->SetNodeInfo(n_as_conf);
    break;
    
  default:
    cerr << "ImportNANRTopology(): Invalid level for imported topology...\n" << flush;
    exit(0);
    
  }

}


void ImportedNLANRTopologyModel::PlaceEdge(Graph* g, int nidfrom, int nidto) {

  static int num_edges = 0;

  try {

    /* Add new edge to graph */
    Node* Src = g->GetNodePtr(nidfrom);
    Node* Dst = g->GetNodePtr(nidto);
    Edge* edge = new Edge( Src, Dst );
    g->AddEdge(edge);
    Src->SetOutDegree(Src->GetOutDegree() + 1);
    Dst->SetInDegree(Dst->GetInDegree() + 1);
    edge->SetDirection(true);

    RouterEdgeConf* e_rt_conf;
    ASEdgeConf* e_as_conf;

    switch (level) {
    case ImportedFileModel::RT_LEVEL:

      e_rt_conf = new RouterEdgeConf(edge->Length());
      e_rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
      e_rt_conf->SetBW(0.0);
      edge->SetConf(e_rt_conf);
      break;

    case ImportedFileModel::AS_LEVEL:

      e_as_conf = new ASEdgeConf();
      e_as_conf->SetEdgeType(EdgeConf::AS_EDGE);
      e_as_conf->SetBW(0.0);
      edge->SetConf(e_as_conf);
      break;
      
    default:
      cerr << "ImporGTITMTopology(): Invalid level for imported topology...\n" << flush;
      exit(0);
    }

    /* Update adjacency list */
    g->AddAdjListNode(nidfrom, nidto);

    num_edges += 1;

  }
  catch (bad_alloc) {
    cerr << "Interconnect(): Cannot allocate new edge...\n" << flush;
    exit(0);
  }

}


Graph* ImportedInetTopologyModel::ParseFile() {

  int i;

  /* Keep information about topology read */
  string model_string;

  /* Initialize vector of tokens */
  vector<string> toks(MAXLINE);

  /* Open file for parsing */
  Parse p((char*)filename.c_str());

  model_string = "Imported Inet topology\n";

  while ((i = p.GetNextTokenList(toks)) == 0);
  if (i < 0) p.ParseError("Model information", "EOF");

  num_strings = 1;

  int nodes = atoi(toks[0].c_str());
  int edges = atoi(toks[1].c_str());

  Graph* graph = new Graph(nodes);

  for (int j = 0; j < nodes; j++) {

    while ((i = p.GetNextTokenList(toks)) == 0);
    if (i < 0) p.ParseError("Node lines", "EOF");
    int nid = atoi(toks[0].c_str()); 
    double x = atof(toks[1].c_str()); 
    double y = atof(toks[2].c_str());

    try {

      /* Add node to Graph */
      Node* node = new Node(j);
      graph->AddNode(node, j);
      node->SetId(nid);

      RouterNodeConf* n_rt_conf;
      ASNodeConf* n_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	/* Set information specific to router nodes */
	n_rt_conf = new RouterNodeConf();
	n_rt_conf->SetCoord(x, y, 0.0); 
	n_rt_conf->SetNodeType(NodeConf::RT_NODE);
	node->SetNodeInfo(n_rt_conf);
	break;
	
      case ImportedFileModel::AS_LEVEL:

	/* Set information specific to AS nodes */
	n_as_conf = new ASNodeConf();
	n_as_conf->SetCoord(x, y, 0.0); 
	n_as_conf->SetNodeType(NodeConf::AS_NODE);
	n_as_conf->SetASId(j);
	n_as_conf->SetTopology(NULL, 0);
	node->SetNodeInfo(n_as_conf);
	break;

      default:
	cerr << "ImportInetTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);

      }
    }
    catch (bad_alloc) {
      cerr << "ImportInetTopology(): Cannot allocate new node...\n" << flush;
      exit(0);
    }
  }

  /* Parse Edges */
  for (int j = 0; j < edges; j++) {
    
    while ((i = p.GetNextTokenList(toks)) == 0);
    if (i < 0) p.ParseError("Edge information", "EOF");			 
    
    int nfrom = atoi(toks[0].c_str());
    int nto = atoi(toks[1].c_str());
    double len = atof(toks[2].c_str());

    Node* Src = graph->GetNodePtr(nfrom);
    Node* Dst = graph->GetNodePtr(nto);

    try {

      /* Add new edge to graph */
      Edge* edge = new Edge(graph->GetNodePtr(nfrom), graph->GetNodePtr(nto));
      graph->AddEdge(edge);

      RouterEdgeConf* e_rt_conf;
      ASEdgeConf* e_as_conf;

      switch (level) {
      case ImportedFileModel::RT_LEVEL:

	e_rt_conf = new RouterEdgeConf(len);
	e_rt_conf->SetEdgeType(EdgeConf::RT_EDGE);
	edge->SetConf(e_rt_conf);
	break;

      case ImportedFileModel::AS_LEVEL:

	e_as_conf = new ASEdgeConf();
	e_as_conf->SetEdgeType(EdgeConf::AS_EDGE);
	edge->SetConf(e_as_conf);
	break;

      default:
	cerr << "ImportInetTopology(): Invalid level for imported topology...\n" << flush;
	exit(0);
      }
      /* Update adjacency lists */
      graph->AddAdjListNode(nfrom, nto);
      graph->AddAdjListNode(nto, nfrom);

      Src->SetOutDegree(Src->GetOutDegree() + 1);
      Dst->SetInDegree(Dst->GetInDegree() + 1);

    }
    catch (bad_alloc) {
      cerr << "ImportedInetTopology Interconnect(): Cannot allocate new edge...\n" << flush;
      exit(0);
    }

  }


  return graph;
}
