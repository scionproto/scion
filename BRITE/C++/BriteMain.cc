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
#include <cstdlib>
#include <iostream>

#include "Brite.h"

class BriteMain {

public:

  void InitSeeds(char *);
  void OutputSeeds(char *);

private:
  
  Topology* topology;
  Model* model;

};


void BriteMain::InitSeeds(char *file_name) {

  ofstream last_seed_file;

  /* Create Parse object */
  Parse p(file_name);

  /* Parse configuration file */
  p.ParseSeed("PLACES", Model::s_places);
  p.ParseSeed("CONNECT", Model::s_connect);
  p.ParseSeed("EDGE_CONN", Model::s_edgeconn);
  p.ParseSeed("GROUPING", Model::s_grouping);
  p.ParseSeed("ASSIGNMENT", Model::s_assignment);
  p.ParseSeed("BANDWIDTH", Model::s_bandwidth);

  cout << "Place seed used: "  
       << Model::s_places[0] << " "
       << Model::s_places[1] << " "
       << Model::s_places[2] << "\n";
  cout << "Connect seed used: " 
       << Model::s_connect[0] << " "
       << Model::s_connect[1] << " "
       << Model::s_connect[2] << "\n";
  cout << "Edge conn seed used: " 
       << Model::s_edgeconn[0] << " "
       << Model::s_edgeconn[1] << " "
       << Model::s_edgeconn[2] << "\n";
  cout << "Grouping seed used: " 
       << Model::s_grouping[0] << " "
       << Model::s_grouping[1] << " "
       << Model::s_grouping[2] << "\n";
  cout << "Assigment seed used: " 
       << Model::s_assignment[0] << " "
       << Model::s_assignment[1] << " "
       << Model::s_assignment[2] << "\n";
  cout << "Bandwidth seed used: " 
       << Model::s_bandwidth[0] << " "
       << Model::s_bandwidth[1] << " "
       << Model::s_bandwidth[2] << "\n" << flush;


  last_seed_file.open("last_seed_file", ios::out);

  if (last_seed_file.fail()) {
    cerr << "Cannot open seed files for input/output...\n";
    exit(0);
  }
  
  last_seed_file << "PLACES"
		 << " " << Model::s_places[0] 
		 << " " << Model::s_places[1] 
		 << " " << Model::s_places[2] << "\n";

  last_seed_file << "CONNECT"
		 << " " << Model::s_connect[0] 
		 << " " << Model::s_connect[1] 
		 << " " << Model::s_connect[2] << "\n";

  last_seed_file << "EDGE_CONN"
		 << " " << Model::s_edgeconn[0] 
		 << " " << Model::s_edgeconn[1] 
		 << " " << Model::s_edgeconn[2] << "\n";

  last_seed_file << "GROUPING"
		 << " " << Model::s_grouping[0] 
		 << " " << Model::s_grouping[1] 
		 << " " << Model::s_grouping[2] << "\n";

  last_seed_file << "ASSIGNMENT"
		 << " " << Model::s_assignment[0] 
		 << " " << Model::s_assignment[1] 
		 << " " << Model::s_assignment[2] << "\n";

  last_seed_file << "BANDWIDTH"
		 << " " << Model::s_bandwidth[0] 
		 << " " << Model::s_bandwidth[1] 
		 << " " << Model::s_bandwidth[2] << "\n";

  last_seed_file.close();
  
}

void BriteMain::OutputSeeds(char *file_name) {

  ofstream seed_file;
  seed_file.open(file_name, ios::out);
  
  if (seed_file.fail()) {
    cerr << "Cannot open seed files for input/output...\n";
    exit(0);
  }
  
  seed_file << "PLACES"
	    << " " << Model::s_places[0] 
	    << " " << Model::s_places[1] 
	    << " " << Model::s_places[2] << "\n";

  seed_file << "CONNECT"
	    << " " << Model::s_connect[0] 
	    << " " << Model::s_connect[1] 
	    << " " << Model::s_connect[2] << "\n";

  seed_file << "EDGE_CONN"
	    << " " << Model::s_edgeconn[0] 
	    << " " << Model::s_edgeconn[1] 
	    << " " << Model::s_edgeconn[2] << "\n";
  
  seed_file << "GROUPING"
	    << " " << Model::s_grouping[0] 
	    << " " << Model::s_grouping[1] 
	    << " " << Model::s_grouping[2] << "\n";

  seed_file << "ASSIGNMENT"
	    << " " << Model::s_assignment[0] 
	    << " " << Model::s_assignment[1] 
	    << " " << Model::s_assignment[2] << "\n";

  seed_file << "BANDWIDTH"
	    << " " << Model::s_bandwidth[0] 
	    << " " << Model::s_bandwidth[1] 
	    << " " << Model::s_bandwidth[2] << "\n";

  cout << "Place seed stored: " 
       << Model::s_places[0] << " "
       << Model::s_places[1] << " "
       << Model::s_places[2] << "\n";
  cout << "Connect seed stored: " 
       << Model::s_connect[0] << " "
       << Model::s_connect[1] << " "
       << Model::s_connect[2] << "\n";
  cout << "Edge Connect seed stored: " 
       << Model::s_edgeconn[0] << " "
       << Model::s_edgeconn[1] << " "
       << Model::s_edgeconn[2] << "\n";
  cout << "Grouping seed used: " 
       << Model::s_grouping[0] << " "
       << Model::s_grouping[1] << " "
       << Model::s_grouping[2] << "\n";
  cout << "Assignment seed stored: " 
       << Model::s_assignment[0] << " "
       << Model::s_assignment[1] << " "
       << Model::s_assignment[2] << "\n";
  cout << "Bandwidth seed stored: " 
       << Model::s_bandwidth[0] << " "
       << Model::s_bandwidth[1] << " "
       << Model::s_bandwidth[2] << "\n" << flush;
  seed_file.close();

}

int main(int argc, char* argv[]) {

  Topology* topology;
  RouterWaxman* rt_wax_model;
  RouterBarabasiAlbert_1* rt_bar_1_model;
  RouterBarabasiAlbert_2* rt_bar_2_model;
  RouterGLP* rt_glp_model;
  ASWaxman* as_wax_model;
  ASBarabasiAlbert_1* as_bar_1_model;
  ASBarabasiAlbert_2* as_bar_2_model;
  ASGLP* as_glp_model;
  TopDownHierModel* td_model;
  BottomUpHierModel* bu_model;
  ImportedBriteTopologyModel* if_brite_model;
  ImportedGTitmTopologyModel* if_gtitm_model;  
  ImportedNLANRTopologyModel* if_nlanr_model;
  ImportedInetTopologyModel* if_inet_model;

  BriteMain m;
  ModelPar* par;

  if (argc < 4) {
    cerr << "run cppgen <config-file> <output-file> <seed-file>\n";
    exit(0);
  }

  /* Init seed used in generation */
  m.InitSeeds(argv[3]);

  /* Create Parse object */
  Parse p(argv[1]);

  /* Parse configuration file */
  par = p.ParseConfigFile();
  assert(par != NULL);

  switch (par->GetModelType()) {
  case RT_WAXMAN:
    rt_wax_model = new RouterWaxman((RouterWaxPar*)par);
    topology = new Topology(rt_wax_model);
    break;

  case RT_BARABASI_1:
    rt_bar_1_model = new RouterBarabasiAlbert_1((RouterBarabasiAlbert_1_Par*)par);
    topology = new Topology(rt_bar_1_model);
    break;

  case RT_BARABASI_2:
    rt_bar_2_model = new RouterBarabasiAlbert_2((RouterBarabasiAlbert_2_Par*)par);
    topology = new Topology(rt_bar_2_model);
    break;

  case RT_GLP:
    rt_glp_model = new RouterGLP((RouterGLPPar*)par);
    topology = new Topology(rt_glp_model);
    break;

  case AS_WAXMAN:
    as_wax_model = new ASWaxman((ASWaxPar*)par);
    topology = new Topology(as_wax_model);
    break;

  case AS_BARABASI_1:
    as_bar_1_model = new ASBarabasiAlbert_1((ASBarabasiAlbert_1_Par*)par);
    topology = new Topology(as_bar_1_model);
    break;

  case AS_BARABASI_2:
    as_bar_2_model = new ASBarabasiAlbert_2((ASBarabasiAlbert_2_Par*)par);
    topology = new Topology(as_bar_2_model);
    break;

  case AS_GLP:
    as_glp_model = new ASGLP((ASGLPPar*)par);
    topology = new Topology(as_glp_model);
    break;

  case TD_HIER:
    td_model = new TopDownHierModel((TopDownPar*)par);
    topology = new Topology(td_model);
    break;

  case BU_HIER:
    bu_model = new BottomUpHierModel((BottUpPar*)par);
    topology = new Topology(bu_model);
    break;

  case IF_ROUTER:
  case IF_AS:

    switch (((ImportedFilePar*)par)->GetFormat()) {
    case ImportedFileModel::IF_BRITE:
      cout << "Importing brite...\n" << flush;
      if_brite_model = new ImportedBriteTopologyModel((ImportedFilePar*)par);
      topology = new Topology(if_brite_model);
      break;

    case ImportedFileModel::IF_GTITM:
    case ImportedFileModel::IF_GTITM_TS:
      cout << "Importing gtitm...\n" << flush;
      if_gtitm_model = new ImportedGTitmTopologyModel((ImportedFilePar*)par);
      topology = new Topology(if_gtitm_model);
      break;

    case ImportedFileModel::IF_NLANR:
      cout << "Importing nlanr..\n" << flush;
      cout.flush();
      if_nlanr_model = new ImportedNLANRTopologyModel((ImportedFilePar*)par);
      topology = new Topology(if_nlanr_model);
      break;

    case ImportedFileModel::IF_INET:
      cout << "Importing Inet..\n" << flush;
      if_inet_model = new ImportedInetTopologyModel((ImportedFilePar*)par);
      topology = new Topology(if_inet_model);
      break;

    case ImportedFileModel::IF_SKITTER:
    default:
      cerr << "BriteMaiin(): Invalid file format for ImportedFileModel...\n";
      exit(0);
    }
    break;

  default:
    cerr << "Parsing error: invalid parameter structure returned...\n";
    exit(0);

  }

  // Check connectivity of topology
  if (!topology->IsConnected()) {
    cout << "Topology is not connected...\n" << flush;
  }else {
    cout << "Topology is connected!!!\n" << flush;
  }

  // Run classification algorithm
  // topology->Classify();

  // Output topology into file(s)
  if (p.OutputBrite()) {
    cout << "Outputing topology into BRITE's format...\n" << flush;
    topology->BriteOutput(argv[2]);
  };
  
  // XXX   Java framework does this so best to call ../bin/brite2otter <britefile> (Anukool)
  /*if (p.OutputOtter()) {
    cout << "Outputing topology into Otter's format...\n" << flush;
    topology->OtterOutput(argv[2]);
    }
  */
  

  delete topology;

  m.OutputSeeds(argv[3]);
  
  cout << "Done!\n";
  return 0;

}


