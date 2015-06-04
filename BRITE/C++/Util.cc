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
#pragma implementation "Util.h"

#include "Util.h"

RandomVariable::RandomVariable(unsigned short int *s) {

  assert(s != NULL);
  seed[0] = s[0];
  seed[1] = s[1];
  seed[2] = s[2];
  sptr = s;

}

RandomVariable::~RandomVariable() {

  assert(sptr != NULL);
  sptr[0] = seed[0];
  sptr[1] = seed[1];
  sptr[2] = seed[2];

}

double RandomVariable::GetValNormal(double avg, double std) {
  
  static int parity = 0;
  static double nextresult;
  double sam1, sam2, rad;
   
  if (std == 0) return avg;
  if (parity == 0) {
    sam1 = 2 * GetValUniform() - 1;
    sam2 = 2 * GetValUniform() - 1;
    while ((rad = sam1*sam1 + sam2*sam2) >= 1) {
      sam1 = 2 * GetValUniform() - 1;
      sam2 = 2 * GetValUniform() - 1;
    }
    rad = sqrt((-2*log(rad))/rad);
    nextresult = sam2 * rad;
    parity = 1;
    return (sam1 * rad * std + avg);
  }
  else {
    parity = 0;
    return (nextresult * std + avg);
  }
}


void BucketSort(vector<double>& A)
{

  vector< list<double> > B(A.size());

  vector<double>::iterator it;

  for (it = A.begin(); it != A.end(); it++) {
    int index = (int)floor(*it * A.size());
    B[index].insert(B[index].begin(), *it);
  }

  list<double>::iterator li;

  int j = 0;
  for (unsigned int i = 0; i < A.size(); i++) {
    B[i].sort();
    for (li = B[i].begin(); li != B[i].end(); li++) {
      A[j++] = *li;
    }
  }

}


int BinarySearch(vector<double>& A, int l, int h, double value) {

  int mid = (h + l)/2;

  if (l == h) return mid;

  if (A[mid] < value) {
    return BinarySearch(A, mid + 1, h, value);
  }else {
    return BinarySearch(A, l, mid, value);
  }

}





 

