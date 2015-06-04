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
#include "Parser.h"
#include "Models/Model.h"

#include <algo.h>

namespace std {
    class istrstream;
}

Parse::Parse(char* f) : delimiters(6), output_formats(2) {
  
  assert(f != NULL);
  infile.open(f, ios::in);
  if (infile.fail()) {
    cerr << "Parse(): cannot open input file " << f << "\n" << flush;
    exit(0);
  }

  /* delimiters used by parser */
  delimiters[0] = 0x20; // space
  delimiters[1] = 0x9;  // tab
  delimiters[2] = 0x3A; // :
  delimiters[3] = 0xA;  // \n
  delimiters[4] = 0x2F; // '/'

}

Parse::~Parse() {
  
  infile.close();

}


int Parse::FileSize() {
  
  int lines = -1;
  char buf[10000];

  while (!infile.eof()) {
    lines++;
    infile.getline(buf, 10000);
  }

  infile.seekg(0, ios::beg);
  infile.clear();

  return lines;

}

void Parse::ResetFilePointer() {
  
  infile.seekg(0, ios::beg);
  infile.clear();

}

bool Parse::IsComment(char ch) {

  if (ch == 0x23) return true;
  return false;

}


bool Parse::IsDelim(char ch) {

  for (unsigned int i = 0; i < delimiters.size(); i++) {
    if (delimiters[i] ==  ch) { 
      return true;
    }
  }
  
  return false;

}


RouterWaxPar::RouterWaxPar(int n, int hs, int ls, int np, 
			   int ig, int m_edges, double a, double b, 
			   int bw, double bw_min, double bw_max) {

  N = n;
  HS = hs;
  LS = ls;
  NP = np;
  IG = ig;
  m = m_edges;
  alpha = a;
  beta = b;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;

}

ASWaxPar::ASWaxPar(int n, int hs, int ls, int np, 
		   int ig, int m_edges, double a, double b, 
		   int bw, double bw_min, double bw_max) {
  HS = hs;
  LS = ls;
  N = n;
  NP = np;
  IG = ig;
  m = m_edges;
  alpha = a;
  beta = b;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;

}

RouterBarabasiAlbert_1_Par::RouterBarabasiAlbert_1_Par(int n, int hs, int ls, int np, 
				     int m_edges, int bw, double bw_min, 
				     double bw_max) {

  HS = hs;
  LS = ls;
  N = n;
  NP = np;
  m = m_edges;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;

}

RouterBarabasiAlbert_2_Par::RouterBarabasiAlbert_2_Par(int n, int hs, int ls, int np, 
				     int m_edges, int bw, double bw_min, 
				     double bw_max, double prob_p, double prob_q) {

  HS = hs;
  LS = ls;
  N = n;
  NP = np;
  m = m_edges;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;
  assert(prob_p >= 0 && prob_p <= 1);
  assert(prob_q >= 0 && prob_q <= 1);
  P = prob_p;
  Q = prob_q;

}

ASBarabasiAlbert_1_Par::ASBarabasiAlbert_1_Par(int n, int hs, int ls, int np, 
			     int m_edges, int bw, double bw_min, 
			     double bw_max) {

  HS = hs;
  LS = ls;
  N = n;
  NP = np;
  m = m_edges;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;

}

ASBarabasiAlbert_2_Par::ASBarabasiAlbert_2_Par(int n, int hs, int ls, int np, 
			     int m_edges, int bw, double bw_min, 
			     double bw_max, double prob_p, double prob_q) {

  HS = hs;
  LS = ls;
  N = n;
  NP = np;
  m = m_edges;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;
  assert(prob_p >= 0 && prob_p <= 1);
  assert(prob_q >= 0 && prob_q <= 1);
  P = prob_p;
  Q = prob_q;

}


TopDownPar::TopDownPar(int ec, int K, 
		       int bw_inter, double bw_inter_min, double bw_inter_max,
		       int bw_intra, double bw_intra_min, double bw_intra_max) {
    EC = ec;
    k = K;
    BWInter = bw_inter;
    BWIntermin = bw_inter_min;
    BWIntermax = bw_inter_max;
    BWIntra = bw_intra;
    BWIntramin = bw_intra_min;
    BWIntramax = bw_intra_max;
}

BottUpPar::BottUpPar(int gm, int at, int m,
		     int bw_inter, double bw_inter_min, double bw_inter_max) {
  
  as_nodes = m;
  GM = gm;
  AT = at;
  BWInter = bw_inter;
  BWIntermin = bw_inter_min;
  BWIntermax = bw_inter_max;

}

ImportedFilePar::ImportedFilePar(string f, FileFormat t, 
				 int hs, int ls, int bw, 
				 double bw_min, double bw_max) {

  filename = f;
  format = t;
  HS = hs;
  LS = ls;
  BW = bw;
  BWmin = bw_min; 
  BWmax = bw_max; 
  
}

RouterGLPPar::RouterGLPPar(int n, int hs, int ls, int np, 
				     int m_edges, int bw, double bw_min, 
				     double bw_max, double p, double beta) {

  HS = hs;
  LS = ls;
  N = n;
  NP = np;
  m = m_edges;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;
  P = p;
  BETA = beta;

}


ASGLPPar::ASGLPPar(int n, int hs, int ls, int np, 
			     int m_edges, int bw, double bw_min, 
			     double bw_max, double p, double beta) {

  HS = hs;
  LS = ls;
  N = n;
  NP = np;
  m = m_edges;
  BW = bw;
  BWmin = bw_min;
  BWmax = bw_max;
  P = p;
  BETA = beta;

}

int Parse::GetNextToken(string& toks) {

  int j = 0;
  char ch;
  char buf[MAXLINE];

  toks.resize(0);

  while (!infile.eof()) {

    infile.get(ch);    

    while (IsDelim(ch) && !infile.eof()) {
      infile.get(ch); 
    }

    if (infile.eof()) {
      return 0;
    }
    
    if (IsComment(ch)) {
      infile.getline(buf, MAXLINE);
      continue; 
    }
    
    while (!IsDelim(ch) && !infile.eof()) {
      toks += ch;
      j++;
      infile.get(ch);
    }

    break;

  }

  return j;

}

int Parse::GetNextTokenList(vector<string>& toks) {

  char buf[MAXLINE];
  string token_read;

  infile.getline(buf, MAXLINE);
  if (infile.eof()) {
    return -1;
  }

  //  istrstream line(buf);
  istringstream line(buf);
  int i = 0;
  while (line >> token_read) {
    if (token_read[0] == '#') {      
      return i;
    }
    toks[i] = token_read;
    i++;
  }

  return i;

}



int Parse::GetNextTokenList(string& from, int& pos, vector<string>& toks) {

  if ((int)from.length() <= pos) {
    return -1;
  }

  delimiters[5] = '.';

  int i = 0, j = 0;
  toks[i] = "";
  while (pos < (int)from.length()) {
    char ch = from[pos];
    if (IsDelim(ch)) {
      i++; j = 0;
      pos++; toks[i] = "";
      continue;
    };
    toks[i] += ch;
    pos++;
  }
  if (pos == (int)from.length()) i++;

  delimiters[5] = ' ';

  return i;

}


void Parse::ParseError(char* e, string g) {


  cerr << "Invalid configuration file...\n" << flush;
  cerr << "Expected " << e << " and got " << g << "\n" << flush;
  exit(0);

}

void Parse::ParseError(char* e, char *g) {


  cerr << "Invalid configuration file...\n" << flush;
  cerr << "Expected " << e << " and got " << g << "\n" << flush;
  exit(0);

}

void Parse::ParseError(string e, char *g) {


  cerr << "Invalid configuration file...\n" << flush;
  cerr << "Expected " << e << " and got " << g << "\n" << flush;
  exit(0);

}

void Parse::ParseIntField(int &v) {

  string toks;

  int i = GetNextToken(toks);
  if ((i == 0)) ParseError("int value", "NULL");
  
  v = atoi(toks.c_str());

}

void Parse::ParseIntField(char* f, int &v) {
  
  int i;
  string toks;

  i = GetNextToken(toks);
  if ((i == 0) || (toks != f )) {
    ParseError(f, toks);
  }

  i = GetNextToken(toks);
  if ((i == 0) || (toks !=  "=")) {
    ParseError("=", toks);
  }

  i = GetNextToken(toks);
  if ((i == 0)) ParseError("int value", "NULL");

  v = atoi(toks.c_str());

}

void Parse::ParseDoubleField(char* f, double &v) {

  int i;
  string toks;

  i = GetNextToken(toks);
  if ((i == 0) ||  (toks != f)) {
    ParseError(f, toks);
  }

  i = GetNextToken(toks);
  if ((i == 0) || (toks != "=")) {
    ParseError("=", toks);
  }

  i = GetNextToken(toks);
  if (i == 0) ParseError("double value", toks);

  v = atof(toks.c_str());

}

void Parse::ParseStringField(char* f) {

  int i;
  string toks;
  i = GetNextToken(toks);
  if ((i == 0) || (toks != f)) 
    ParseError(f, toks);
}

void Parse::ParseStringField(char* f, string& s) {

  int i;
  string toks;

  i = GetNextToken(toks);   
  if ((i == 0) || (toks != f)) ParseError(f, toks);

  i = GetNextToken(toks);   
  if ((i == 0) || (toks != "=")) ParseError("=",  toks);

  i = GetNextToken(toks);   
  if (i == 0) ParseError("string field",  toks);

  s = toks;

}


void Parse::ParseSeed(char* f, unsigned short int seed[]) {

  int i;
  string toks;

  i = GetNextToken(toks);
  if ((i == 0) || (toks != f)) ParseError(f, toks);
  i = GetNextToken(toks);
  if (i == 0) ParseError("Seed value", toks);
  seed[0] = atoi(toks.c_str());
  i = GetNextToken(toks);
  if (i == 0) ParseError("Seed value", toks);
  seed[1] = atoi(toks.c_str());
  i = GetNextToken(toks);
  if (i == 0) ParseError("Seed value", toks);
  seed[2] = atoi(toks.c_str());

}


RouterWaxPar* Parse::ParseRouterWaxman() {

  int n, hs, ls, np, ig, m, bw;
  double bw_min, bw_max;
  double a, b;

  RouterWaxPar* rt_wax_par;
  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("GrowthType", ig);
  ParseIntField("m", m);
  ParseDoubleField("alpha", a);
  ParseDoubleField("beta", b);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseStringField("EndModel");

  try {

    rt_wax_par = new RouterWaxPar(n, hs, ls, np, ig, m, a, b, bw, bw_min, bw_max);
    rt_wax_par->SetModelType(1);

  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return rt_wax_par;
}

ASWaxPar* Parse::ParseASWaxman() {

  int n, hs, ls, np, ig, m, bw;
  double a, b, bw_min, bw_max;
  ASWaxPar* as_wax_par;

  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("GrowthType", ig);
  ParseIntField("m", m);
  ParseDoubleField("alpha", a);
  ParseDoubleField("beta", b);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseStringField("EndModel");

  try {

    as_wax_par = new ASWaxPar(n, hs, ls, np, ig, m, a, b, bw, bw_min, bw_max);
    as_wax_par->SetModelType(3);

  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return as_wax_par;
  
}


RouterBarabasiAlbert_1_Par* Parse::ParseRouterBarabasiAlbert_1() {

  int n, hs, ls, np, m, bw;
  double bw_min, bw_max;
  RouterBarabasiAlbert_1_Par* rt_bar_par;

  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("m", m);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseStringField("EndModel");

  try {

    rt_bar_par = new RouterBarabasiAlbert_1_Par(n, hs, ls, np, m, bw, bw_min, bw_max);
    rt_bar_par->SetModelType(2);

  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return rt_bar_par;

}


RouterBarabasiAlbert_2_Par* Parse::ParseRouterBarabasiAlbert_2() {

  int n, hs, ls, np, m, bw;
  double bw_min, bw_max, p, q;
  RouterBarabasiAlbert_2_Par* rt_bar_par;

  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("m", m);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseDoubleField("p", p);
  ParseDoubleField("q", q);
  ParseStringField("EndModel");

  try {

    rt_bar_par = new RouterBarabasiAlbert_2_Par(n, hs, ls, np, m, bw, bw_min, bw_max, p, q);
    rt_bar_par->SetModelType(9);

  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return rt_bar_par;

}

ASBarabasiAlbert_1_Par* Parse::ParseASBarabasiAlbert_1() {

  int n, hs, ls, np, m, bw;
  double bw_min, bw_max;
  ASBarabasiAlbert_1_Par* as_bar_par;

  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("m", m);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseStringField("EndModel");

  try {

    as_bar_par = new ASBarabasiAlbert_1_Par(n, hs, ls, np, m, bw, bw_min, bw_max);
    as_bar_par->SetModelType(4);
  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return as_bar_par;

}

ASBarabasiAlbert_2_Par* Parse::ParseASBarabasiAlbert_2() {

  int n, hs, ls, np, m, bw;
  double bw_min, bw_max, p, q;
  ASBarabasiAlbert_2_Par* as_bar_par;

  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("m", m);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseDoubleField("p", p);
  ParseDoubleField("q", q);
  ParseStringField("EndModel");

  try {

    as_bar_par = new ASBarabasiAlbert_2_Par(n, hs, ls, np, m, bw, bw_min, bw_max, p, q);
    as_bar_par->SetModelType(10);
  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return as_bar_par;

}


TopDownPar* Parse::ParseTopDownHier() {

  int ec, k, model;
  int bw_inter, bw_intra, bw_inter_min, bw_intra_min;
  int bw_inter_max, bw_intra_max;
  RouterWaxPar* rt_wax_par;
  ASWaxPar* as_wax_par;
  RouterBarabasiAlbert_1_Par* rt_bar_1_par;
  RouterBarabasiAlbert_2_Par* rt_bar_2_par;
  ASBarabasiAlbert_1_Par* as_bar_1_par;
  ASBarabasiAlbert_2_Par* as_bar_2_par;
  TopDownPar* td_par;
  ImportedFilePar* if_par;
  
  ParseIntField("edgeConn", ec);
  ParseIntField("k", k);
  ParseIntField("BWInter", bw_inter);
  ParseIntField("BWInterMin", bw_inter_min);
  ParseIntField("BWInterMax", bw_inter_max);
  ParseIntField("BWIntra", bw_intra);
  ParseIntField("BWIntraMin", bw_intra_min);
  ParseIntField("BWIntraMax", bw_intra_max);
  ParseStringField("EndModel");
  
  try {
    td_par = new TopDownPar(ec, k, bw_inter, bw_inter_min,
			    bw_inter_max, bw_intra, bw_intra_min,
			    bw_intra_max);
    td_par->SetModelType(5);
  }
  catch (bad_alloc) {
    cerr << "Cannot allocate TopDown parameters...\n" << flush;
    exit(0);
  }

  ParseStringField("BeginModel");
  ParseIntField("Name", model);

  switch (model) {
  case 3:
    cout << "Parsing AS Waxman model...\n" << flush;
    as_wax_par = ParseASWaxman();
    as_wax_par->SetBW(td_par->GetBWInter());
    as_wax_par->SetBWMin(td_par->GetBWInterMin());
    as_wax_par->SetBWMax(td_par->GetBWInterMax());
    td_par->SetModelPar(0, as_wax_par);
    break;
    
  case 4:
    cout << "Parsing AS BarabasiAlbert-1 model...\n" << flush;
    as_bar_1_par = ParseASBarabasiAlbert_1();
    as_bar_1_par->SetBW(td_par->GetBWInter());
    as_bar_1_par->SetBWMin(td_par->GetBWInterMin());
    as_bar_1_par->SetBWMax(td_par->GetBWInterMax());
    td_par->SetModelPar(0, as_bar_1_par);
    break;
    
  case 8:
    cout << "Parsing Imported file model...\n" << flush;
    if_par = ParseImportedFile(model);
    td_par->SetModelPar(0, if_par);
    break;

  case 10:
    cout << "Parsing AS BarabasiAlbert-2 model...\n" << flush;
    as_bar_2_par = ParseASBarabasiAlbert_2();
    as_bar_2_par->SetBW(td_par->GetBWInter());
    as_bar_2_par->SetBWMin(td_par->GetBWInterMin());
    as_bar_2_par->SetBWMax(td_par->GetBWInterMax());
    td_par->SetModelPar(0, as_bar_2_par);
    break;
    
  default:
    cerr << "Invalid model type for level 1 of hierarchical topology...\n" << flush;
    exit(0);
  }

  ParseStringField("BeginModel");
  ParseIntField("Name", model);

  switch (model) {
  case 1:
    cout << "Parsing Router waxman model...\n" << flush;
    rt_wax_par = ParseRouterWaxman();
    rt_wax_par->SetBW(td_par->GetBWIntra());
    rt_wax_par->SetBWMin(td_par->GetBWIntraMin());
    rt_wax_par->SetBWMax(td_par->GetBWIntraMax());
    td_par->SetModelPar(1, rt_wax_par);
    td_par->SetM(rt_wax_par->GetM());
    break;
    
  case 2:
    cout << "Parsing Router BarabasiAlbert_1 model...\n" << flush;
    rt_bar_1_par = ParseRouterBarabasiAlbert_1();
    rt_bar_1_par->SetBW(td_par->GetBWIntra());
    rt_bar_1_par->SetBWMin(td_par->GetBWIntraMin());
    rt_bar_1_par->SetBWMax(td_par->GetBWIntraMax());
    td_par->SetModelPar(1, rt_bar_1_par);
    td_par->SetM(rt_bar_1_par->GetM());
    break;

  case 7:
    cout << "Parsing Imported file model...\n" << flush;
    if_par = ParseImportedFile(model);
    td_par->SetModelPar(1, if_par);
    td_par->SetM(2);
    break;

  case 9:
    cout << "Parsing Router BarabasiAlbert_2 model...\n" << flush;
    rt_bar_2_par = ParseRouterBarabasiAlbert_2();
    rt_bar_2_par->SetBW(td_par->GetBWIntra());
    rt_bar_2_par->SetBWMin(td_par->GetBWIntraMin());
    rt_bar_2_par->SetBWMax(td_par->GetBWIntraMax());
    td_par->SetModelPar(1, rt_bar_2_par);
    td_par->SetM(rt_bar_2_par->GetM());
    break;

  default:
    cerr << "Invalid model type for level 2 hierarchical topology...\n" << flush;
    exit(0);
  }

  return td_par;

}

BottUpPar* Parse::ParseBottUpHier() {

  int gm, at, model, as_nodes;
  int bw_inter, bw_inter_min, bw_inter_max;
  RouterWaxPar* rt_wax_par;
  RouterBarabasiAlbert_1_Par* rt_bar_par;
  //RouterBarabasiAlbert_2_Par* rt_bar_2_par;
  BottUpPar* bu_par;
  ImportedFilePar* if_par;
  
  ParseIntField("Grouping", gm);
  ParseIntField("AssignType", at);
  ParseIntField("NumAS", as_nodes);
  ParseIntField("BWInter", bw_inter);
  ParseIntField("BWInterMin", bw_inter_min);
  ParseIntField("BWInterMax", bw_inter_max);
  ParseStringField("EndModel");
  
  try {
    bu_par = new BottUpPar(gm, at, as_nodes, bw_inter, 
			   bw_inter_min, bw_inter_max);
    bu_par->SetModelType(6);
  }
  catch (bad_alloc) {
    cerr << "Cannot allocate Bottom Up parameters...\n" << flush;
    exit(0);
  }

  ParseStringField("BeginModel");
  ParseIntField("Name", model);

  switch (model) {

  case 1:
    cout << "Parsing Router Waxman model...\n" << flush;
    rt_wax_par = ParseRouterWaxman();
    bu_par->SetModelPar(0, (ModelPar*)rt_wax_par);
    bu_par->SetM(rt_wax_par->GetM());
    break;
    
  case 2:
    cout << "Parsing Router BarabasiAlbert_1 model...\n" << flush;
    rt_bar_par = ParseRouterBarabasiAlbert_1();
    bu_par->SetModelPar(0, (ModelPar*)rt_bar_par);
    bu_par->SetM(rt_bar_par->GetM());
    break;
    
  case 7:
    cout << "Parsing Imported file model...\n" << flush;
    if_par = ParseImportedFile(model);
    bu_par->SetModelPar(0, if_par);
    bu_par->SetM(2);
    break;
    
  default:
    cerr << "Invalid model type for BU hierarchical topology...\n" << flush;
    exit(0);
  }

  return bu_par;

}


ImportedFilePar* Parse::ParseImportedFile(int model) {

  string f;
  int t, hs, ls, bw;
  double bw_min, bw_max;
  ImportedFilePar* if_par;

  /* For imported configuration files we need '/' to be a non-delimiter */
  delimiters[4] = ' ';

  ParseIntField("Format", t);
  ParseStringField("File", f);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseStringField("EndModel");

  try {

    if_par = new ImportedFilePar(f, (ImportedFilePar::FileFormat)t,
				 hs, ls, bw, bw_min, bw_max);
    if_par->SetModelType(model);

  }
  catch (bad_alloc) {
    cerr << "Cannot allocate parameters for Imported file model...\n" << flush;
    exit(0);
  }
  delimiters[4] = 0x2F;
  return if_par;
}


RouterGLPPar* Parse::ParseRouterGLP() {

  int n, hs, ls, np, m, bw;
  double bw_min, bw_max, p, beta;
  RouterGLPPar* rt_glp_par;

  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("m", m);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseDoubleField("p", p);
  ParseDoubleField("BETA", beta);
  ParseStringField("EndModel");

  try {

    rt_glp_par = new RouterGLPPar(n, hs, ls, np, m, bw, bw_min, bw_max, p, beta);
    rt_glp_par->SetModelType(11);
  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return rt_glp_par;

}


ASGLPPar* Parse::ParseASGLP() {

  int n, hs, ls, np, m, bw;
  double bw_min, bw_max, beta, p;
  ASGLPPar* as_glp_par;

  ParseIntField("N", n);
  ParseIntField("HS", hs);
  ParseIntField("LS", ls);
  ParseIntField("NodePlacement", np);
  ParseIntField("m", m);
  ParseIntField("BWDist", bw);
  ParseDoubleField("BWMin", bw_min);
  ParseDoubleField("BWMax", bw_max);
  ParseDoubleField("p", p);
  ParseDoubleField("BETA", beta);
  ParseStringField("EndModel");

  try {

    as_glp_par = new ASGLPPar(n, hs, ls, np, m, bw, bw_min, bw_max, p, beta);
    as_glp_par->SetModelType(12);
  }
  catch (bad_alloc) {
    cerr << "Cannot allocated parameters...\n" << flush;
    exit(0);
  }
  
  return as_glp_par;

}



ModelPar* Parse::ParseConfigFile() {

  int model;
  RouterWaxPar* rt_wax_par;
  ASWaxPar* as_wax_par;
  RouterBarabasiAlbert_1_Par* rt_bar_1_par;
  RouterBarabasiAlbert_2_Par* rt_bar_2_par;
  RouterGLPPar* rt_glp_par;
  ASBarabasiAlbert_1_Par* as_bar_1_par;
  ASBarabasiAlbert_2_Par* as_bar_2_par;
  ASGLPPar* as_glp_par;
  TopDownPar* td_par;
  BottUpPar* bu_par;
  ImportedFilePar* if_par;
  ModelPar* ret_par;

  /* First line of file */
  ParseStringField("BriteConfig");
  
  /* Next Token */
  ParseStringField("BeginModel");

  /* Name for first model */
  ParseIntField("Name", model);

  switch (model) {
  case RT_WAXMAN:
    cout << "Parsing Router waxman model...\n" << flush;
    rt_wax_par = ParseRouterWaxman();
    ret_par = rt_wax_par;
    break;
    
  case RT_BARABASI_1:
    cout << "Parsing Router BarabasiAlbert-1 model...\n" << flush;
    rt_bar_1_par = ParseRouterBarabasiAlbert_1();
    ret_par = rt_bar_1_par;
    break;

  case RT_BARABASI_2:
    cout << "Parsing Router BarabasiAlbert-2 model...\n" << flush;
    rt_bar_2_par = ParseRouterBarabasiAlbert_2();
    ret_par = rt_bar_2_par;
    break;

  case RT_GLP:
    cout << "Parsing Router GLP model...\n" << flush;
    rt_glp_par = ParseRouterGLP();
    ret_par = rt_glp_par;
    break;
    
  case AS_WAXMAN:
    cout << "Parsing AS Waxman model...\n" << flush;
    as_wax_par = ParseASWaxman();
    ret_par = as_wax_par;
    break;
    
  case AS_BARABASI_1:
    cout << "Parsing AS BarabasiAlbert-1 model...\n" << flush;
    as_bar_1_par = ParseASBarabasiAlbert_1();
    ret_par = as_bar_1_par;
    break;

  case AS_BARABASI_2:
    cout << "Parsing AS BarabasiAlbert-2 model...\n" << flush;
    as_bar_2_par = ParseASBarabasiAlbert_2();
    ret_par = as_bar_2_par;
    break;

  case AS_GLP:
    cout << "Parsing AS GLP model...\n" << flush;
    as_glp_par = ParseASGLP();
    ret_par = as_glp_par;
    break;

  case TD_HIER:
    cout << "Parsing Top-down hierarchical model...\n" << flush;
    td_par = ParseTopDownHier();
    ret_par = td_par;
    break;

  case BU_HIER:
    cout << "Parsing Bottom-Up hierarchichal model...\n" << flush;
    bu_par = ParseBottUpHier();
    assert(bu_par != NULL);
    ret_par = bu_par;
    break;

  case IF_ROUTER:
  case IF_AS:
    cout << "Parsing imported file flat model...\n" << flush;
    if_par = ParseImportedFile(model);
    ret_par = if_par;
    break;

  default:
    cerr << "Parse(): Invalid model id: " << model << "\n" << flush;
    exit(0);
  }

  /* Parse output formats */
  int brite, otter, ns, dml, javasim;
  
  ParseStringField("BeginOutput");

  /* First output format */
  ParseIntField("BRITE", brite);

  /* First output format */
  ParseIntField("OTTER", otter);

  output_formats[0] = brite;
  output_formats[1] = otter;

  /* added by Anukool so that C++ version recognizes the new fields
   (although it doesn't do anything them -- use converter scripts..*/
  ParseIntField("DML", dml);
  ParseIntField("NS", ns);
  ParseIntField("Javasim", javasim);
  
  ParseStringField("EndOutput");

  return ret_par;
  
}


