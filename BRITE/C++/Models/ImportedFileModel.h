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
#ifndef IF_MODEL_H

#define IF_MODEL_H
#pragma interface

#include "Model.h"

////////////////////////////////////////
//
// class ImportedFileModel
// Base class for models that generate 
// topologies imported from files containing
// Previously generated topologies
//
////////////////////////////////////////

class ImportedFilePar;

class ImportedFileModel : public Model {

 public:
  
  enum ImportedFileFormat { IF_BRITE = 1, IF_GTITM = 2, 
			    IF_NLANR = 3, IF_SKITTER = 4, 
			    IF_GTITM_TS = 5, IF_INET = 6 };
  enum Level {RT_LEVEL = 1, AS_LEVEL = 2 };
  ImportedFileModel(ImportedFilePar* par);
  virtual Graph* Generate() { return (Graph*)NULL; }
  ImportedFileFormat GetFileFormat() { return format; }
  int GetBW() { return BWdist; }
  double GetBWMin() { return BWmin; }
  double GetBWMax() { return BWmax; }
  string ToString();
  void AssignBW(Graph* g);
  BWDistType GetBWDist() { return BWdist; }
  void SetBWDist(BWDistType t) { BWdist = t; }
  void SetBWMin(double bw) { BWmin = bw; }
  void SetBWMax(double bw) { BWmax = bw; }

 protected:
  ImportedFileFormat format;
  vector<string> model_strings;
  Level level;
  int num_strings;
  string filename;

 private:
  BWDistType BWdist;
  double BWmin;
  double BWmax;

};


class ImportedBriteTopologyModel : public ImportedFileModel {

 public:
  ImportedBriteTopologyModel(ImportedFilePar* par);
  Graph* Generate(); 

 private:
  Graph* ParseFile();
  
};

class ImportedGTitmTopologyModel : public ImportedFileModel {

 public:
  ImportedGTitmTopologyModel(ImportedFilePar* par);
  Graph* Generate(); 

 private:
  Graph* ParseFile();
  Graph* ParseFlatGTITM();
  Graph* ParseTSGTITM();

};


class ImportedNLANRTopologyModel : public ImportedFileModel {
 public:
  ImportedNLANRTopologyModel(ImportedFilePar* par);
  Graph* Generate(); 

 private:
  Graph* ParseFile();
  void PlaceNode(Graph*, int, string);
  void PlaceEdge(Graph*, int, int);
  RandomVariable U;

};

class ImportedInetTopologyModel : public ImportedFileModel {

 public:
  ImportedInetTopologyModel(ImportedFilePar* par);
  Graph* Generate(); 

 private:
  Graph* ParseFile();
  
};

class ImportedSkitterTopologyModel : public ImportedFileModel {

 public:
  ImportedSkitterTopologyModel(ImportedFilePar* par);
  Graph* Generate();
  int GetNumStrings() { return num_strings; }

 private:
  Graph* ParseFile();

};

#endif /* IF_MODEL_H */


