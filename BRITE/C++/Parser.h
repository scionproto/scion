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
#ifndef PARSER_H
#define PARSER_H

#include "Util.h"

#define MAXLINE 10000
#define MAXFILENAME 50

class ModelPar {

public:
  int GetHS() {return HS;}
  int GetLS() {return LS;}
  void SetHS(int hs) { HS = hs;}
  void SetLS(int ls) { LS = ls;}
  void SetModelType(int t) { model = t; }
  int GetModelType() { return model; }

protected:
  int model;
  int HS;             // Side one of plane
  int LS;             // Inner Side one of plane

};

class RouterWaxPar : public ModelPar{

public:

  RouterWaxPar(int n, int hs, int ls, int np, 
	       int ig, int m_edges, double a, double b, 
	       int bw, double bw_min, double bw_max);

  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetIG() { return IG; }
  int GetM() { return m; }
  double GetA() { return alpha; }
  double GetB() { return beta; }
  int GetBW() { return BW; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }  

private:
  int N;              // Size
  int NP;             // Node placement strategy
  int IG;             // Growth type
  int m;              // Number of edges per newly added node
  double alpha, beta; // Waxman parameters
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;

};

class ASWaxPar : public ModelPar {

public:

  ASWaxPar(int n, int hs, int ls, int np, 
	   int ig, int m_edges, double a, double b, 
	   int bw, double bw_min, double bw_max);

  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetIG() { return IG; }
  int GetM() { return m; }
  double GetA() { return alpha; }
  double GetB() { return beta; }
  int GetBW() { return BW; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }  

private:

  int N;              // Size
  int NP;             // Node placement strategy
  int IG;             // Growth type
  int m;              // Number of edges per newly added node
  double alpha, beta; // Waxman parameters
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;

};

class RouterBarabasiAlbert_1_Par : public ModelPar{

public:

  RouterBarabasiAlbert_1_Par(int n, int hs, int ls, int np, int m_edges, 
		    int bw, double bw_min, double bw_max);

  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetM() { return m; }
  int GetBW() { return BW; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }

private:

  int N;              // Size
  int NP;             // Node placement strategy
  int m;              // Number of edges per newly added node
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;

};

class RouterBarabasiAlbert_2_Par : public ModelPar{

public:

  RouterBarabasiAlbert_2_Par(int n, int hs, int ls, int np, int m_edges, 
		    int bw, double bw_min, double bw_max, double prob_p, double prob_q);

  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetM() { return m; }
  int GetBW() { return BW; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }
  double GetP() { return P; }
  double GetQ() { return Q; }

private:

  int N;              // Size
  int NP;             // Node placement strategy
  int m;              // Number of edges per newly added node
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;
  double P;
  double Q;

};

class ASBarabasiAlbert_1_Par : public ModelPar {

public:

  ASBarabasiAlbert_1_Par(int n, int hs, int ls, int np, int m_edges, 
		int bw, double bw_min, double bw_max);
  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetM() { return m; }
  int GetBW() { return BW; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }

 private:
  int N;              // Size
  int NP;             // Node placement strategy
  int m;              // Number of edges per newly added node
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;

};


class ASBarabasiAlbert_2_Par : public ModelPar {

public:

  ASBarabasiAlbert_2_Par(int n, int hs, int ls, int np, int m_edges, 
		int bw, double bw_min, double bw_max, double p, double q);
  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetM() { return m; }
  int GetBW() { return BW; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  double GetP() { return P; }
  double GetQ() { return Q; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }

 private:
  int N;              // Size
  int NP;             // Node placement strategy
  int m;              // Number of edges per newly added node
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;
  double P;           // Probabilities for rewiring and adding edges
  double Q;

};

class TopDownPar : public ModelPar {

public:

  TopDownPar(int ec, int K, 
	     int bw_inter, double bw_inter_min, double bw_inter_max,
	     int bw_intra, double bw_intra_min, double bw_intra_max);

  void SetModelPar(int i, ModelPar* model) {
    assert(i >= 0 && i <= 1);
    model_pars[i] = model;
  }
  ModelPar* GetModelPar(int i) { return model_pars[i]; }
  int GetK() { return k; }
  int GetEC() { return EC; }
  void SetM(int m) { m_edges = m; }
  int GetM() { return m_edges; }
  int GetBWInter() { return BWInter; }
  double GetBWInterMin() { return BWIntermin; }
  double GetBWInterMax() { return BWIntermax; }
  int GetBWIntra() { return BWIntra; }
  double GetBWIntraMin() { return BWIntramin; }
  double GetBWIntraMax() { return BWIntramax; }

private:

  int EC;             // Edge connection method
  int k;
  int m_edges;
  int BWInter;             // Bandwidth distribution (Inter-domain)
  double BWIntermin;
  double BWIntermax;
  int BWIntra;             // Bandwidth distribution (Intra-somain)
  double BWIntramin;
  double BWIntramax;
  ModelPar* model_pars[2];    // Models for AS and Router-level

};

class BottUpPar : public ModelPar{

public:

  BottUpPar(int gm, int at, int m, 
	    int bw_inter, double bw_inter_min, double bw_inter_max);

  void SetModelPar(int i, ModelPar* model) {
    assert(i >= 0 && i <= 1);
    model_pars[i] = model;
  }
  ModelPar* GetModelPar(int i) { return model_pars[i]; }
  int GetGM() { return GM; }
  int GetAT() { return AT; }
  int GetASNodes() { return as_nodes; }
  void SetM(int m) { m_edges = m; }
  int GetM() { return m_edges; }
  int GetBWInter() { return BWInter; }
  double GetBWInterMin() { return BWIntermin; }
  double GetBWInterMax() { return BWIntermax; }

private:
  int as_nodes;       // Number of AS Nodes
  int GM;             // Groping Method
  int AT;             // Assignment type of routers to ASes
  int m_edges;
  int BWInter;             // Bandwidth distribution (Inter-domain)
  double BWIntermin;
  double BWIntermax;
  ModelPar* model_pars[2];    // Models for AS and Router-level

};

class ImportedFilePar : public ModelPar {

public:

  enum FileFormat {BRITE = 1, GTITM = 2, NLANR = 3, CAIDA = 4};
  ImportedFilePar(string f, FileFormat t, 
		  int hs, int ls, int bw, 
		  double bw_min, double bw_max);
  string GetFileName() { return filename; }
  FileFormat GetFormat() { return format; }
  int GetHS() { return HS; } 
  int GetLS() { return LS; } 
  int  GetBW() { return BW; } 
  double GetBWMin() { return BWmin; } 
  double GetBWMax() { return BWmax; } 

private:

  string filename;
  FileFormat format;
  int HS;
  int LS;
  int BW;
  double BWmin;
  double BWmax;
  
};



class RouterGLPPar : public ModelPar{

public:

  RouterGLPPar(int n, int hs, int ls, int np, 
	       int m_edges, int bw, double bw_min, 
	       double bw_max, double p, double beta);

  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetM() { return m; }
  int GetBW() { return BW; }
  double GetP() { return P; }
  double GetBETA() { return BETA; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }

private:

  int N;              // Size
  int NP;             // Node placement strategy
  int m;              // Number of edges per newly added node
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;
  double P;
  double BETA;

};


class ASGLPPar : public ModelPar {

public:

  ASGLPPar(int n, int hs, int ls, int np, int m_edges, 
		int bw, double bw_min, double bw_max, double p, double beta);
  int GetN() { return N; }
  int GetNP() { return NP; }
  int GetM() { return m; }
  int GetBW() { return BW; }
  double GetP() { return P;}
  double GetBETA() { return BETA; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  void SetBW(int bw) { BW = bw; }
  void SetBWMin(double bw_min) { BWmin = bw_min; }
  void SetBWMax(double bw_max) { BWmax = bw_max; }

 private:
  int N;              // Size
  int NP;             // Node placement strategy
  int m;              // Number of edges per newly added node
  int BW;             // Bandwidth distribution
  double BWmin;
  double BWmax;
  double P;
  double BETA;

};



class Parse {

  friend class ImportedBriteTopologyModel;
  friend class ImportedGTitmTopologyModel;
  friend class ImportedNLANRTopologyModel;
  friend class ImportedInetTopologyModel;

public:

  Parse(char* filename);
  ~Parse();
  ModelPar* ParseConfigFile();
  void ParseSeed(char* f, unsigned short int s[]);
  void ResetFilePointer();
  void ParseError(char* e, string g);
  void ParseError(string e, char* g);
  void ParseError(char* e, char* g);
  bool OutputBrite() { return (output_formats[0] == 1)?true:false;}
  bool OutputOtter() { return (output_formats[1] == 1)?true:false;}

private:

  ifstream infile;
  int GetNextToken(string& a);
  int GetNextTokenList(vector<string>& a);
  int GetNextTokenList(string& from, int& pos, vector<string>& toks);
  void ParseIntField(char* f, int& v);
  void ParseIntField(int& v);
  void ParseDoubleField(char* f, double& v);
  void ParseDoubleField(double& v);
  void ParseStringField(char* f);
  void ParseStringField(char* f, string& s);
  int FileSize();
  bool IsDelim(char ch);
  bool IsComment(char ch);
  vector<char> delimiters;
  vector<int> output_formats;

  RouterWaxPar* ParseRouterWaxman();
  ASWaxPar* ParseASWaxman();
  RouterBarabasiAlbert_1_Par* ParseRouterBarabasiAlbert_1();
  RouterBarabasiAlbert_2_Par* ParseRouterBarabasiAlbert_2();
  ASBarabasiAlbert_1_Par* ParseASBarabasiAlbert_1();
  ASBarabasiAlbert_2_Par* ParseASBarabasiAlbert_2();
  RouterGLPPar* ParseRouterGLP();
  ASGLPPar* ParseASGLP();
  TopDownPar* ParseTopDownHier();
  BottUpPar* ParseBottUpHier();
  ImportedFilePar* ParseImportedFile(int model);

};



#endif /* PARSER_H */
