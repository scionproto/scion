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
#ifndef AS_BAR_MODEL_2_H
#define AS_BAR_MODEL_2_H
#pragma interface

#include "ASBarabasiAlbertModel.h"

class ASBarabasiAlbert_2_Par;

class ASBarabasiAlbert_2 : public ASBarabasiAlbert {
    
 public:
    
  ASBarabasiAlbert_2(ASBarabasiAlbert_2_Par* par);
  string ToString();
    
 private:

  void InterconnectNodes(Graph *g);
  double P;
  double Q;

};


#endif /* AS_BAR_MODEL_2_H */


