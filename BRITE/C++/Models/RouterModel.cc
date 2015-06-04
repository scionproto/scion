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
#pragma implementation "RouterModel.h"

#include "RouterModel.h"

void RouterModel::AssignBW(Graph* g) {

  double v;
  RandomVariable BW(s_bandwidth);

  list<Edge*>::iterator el;
  for (el = g->edges.begin(); el != g->edges.end(); el++) {

    assert((*el)->GetConf()->GetEdgeType() == EdgeConf::RT_EDGE);

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
      cerr << "RouterModel::AssignBW():  invalid BW distribution (" 
	   << (int)BWdist << ")...\n" << flush;
      exit(0);
    }

    (*el)->GetConf()->SetBW(v);
  }

}


void RouterModel::PlaceNodes(Graph* g) {

  double x, y, z;
  int num_squares, num_placed, num;
  Node* node;
  RouterNodeConf* rt_conf; 
  RandomVariable U(s_places);

  int n  = size;
  switch (GetPlacementType()) {

  case P_RANDOM: /* Random Node placement */
    
    cout << "random placement...\n" << flush;
    for (int i = 0; i < n; i++) {
      
      bool found = true;
      do {
	/* Pick random location */
	x = floor(U.GetValUniform((double) Scale_1));
	y = floor(U.GetValUniform((double) Scale_1));
	/* 3rd dimension disabled for now */
	z = 0.0; 
	/* Check for Placement Collision */       
	int tx = (int)x;
	int ty = (int)y;

	found = PlaneCollision(tx, ty);

      }while(found);
      
      try {

	/* Add node to Graph */
	node = new Node(i);
	g->AddNode(node, i);

	/* Set information specific to router nodes */
	rt_conf = new RouterNodeConf();
	rt_conf->SetCoord(x, y, z); 
	rt_conf->SetNodeType(NodeConf::RT_NODE);
	rt_conf->SetRouterType(RouterNodeConf::RT_NONE);
	rt_conf->SetASId(-1);
	node->SetNodeInfo(rt_conf);
	
      }

      catch (bad_alloc) {

	cerr << "PlaceNmodes: could not create new node configuration...\n" << flush;
	exit(0);

      }

    }
    break;

  case P_HT:  /* NodePlacement == HEAVY TAILED */

    cout << "HT Node placement...\n" << flush;
    num_squares = (int)::floor(Scale_1/Scale_2);
    num_placed = 0;
    while (num_placed < n) {
      
      for (int i = 0; i < num_squares; i++) {
	for (int j = 0; j < num_squares; j++) {		 
	  
	  num = (int)floor(U.GetValPareto(1000000*Scale_2*Scale_2, 1.0));
	  num = (num <= (3*Scale_2 * Scale_2/4))?num:(int)(3*Scale_2 * Scale_2/4);
	  
	  for (int k = 0; k < num; k++) { 
	     
	    bool found = true;
	    do {

	       /* Pick random location in proper square*/
	       x = (int)floor(U.GetValUniform((double)Scale_2) + j*Scale_2);
	       y = (int)floor(U.GetValUniform((double)Scale_2) + i*Scale_2);
	       /* 3rd dimension disabled for now */
	       z = 0; 
	       /* Check for Placement Collision */       
	       int tx = (int)x;
	       int ty = (int)y;

	       found = PlaneCollision(tx, ty);

	     }while(found);
	     
	     /* Create Node and Node configuration */
	     try {
	       
	       node = new Node(num_placed);
	       g->AddNode(node, num_placed);
	       
	       /* Set information specific to router nodes */
	       rt_conf = new RouterNodeConf();
	       rt_conf->SetCoord(x, y, z); 
	       rt_conf->SetNodeType(NodeConf::RT_NODE);
	       rt_conf->SetRouterType(RouterNodeConf::RT_NONE);
	       rt_conf->SetASId(-1);
	       node->SetNodeInfo(rt_conf);
	       
	     }
	     catch (bad_alloc) {
	       cerr << "PlaceNode: could not create new node configuration\n" << flush;
	       exit(0);
	     }
	     
	     /* keep trace of num of nodes placed */
	     num_placed++;
	     if (num_placed >= n) {
	       break;
	     }
	   }
	   
	   if (num_placed >= n) {
	     break;
	   }
	 }
	 if (num_placed >= n) {
	   break;
	 }
       }

     }

     g->SetNumNodes(num_placed);
     cout << "Number of nodes placed: " << num_placed << "\n" << flush;
     break;

  default:
       
    cout << "Invalid Node Placement Model...\n" << flush;
    assert(0);
       
  }
  cout << "done!\n" << flush;
}


