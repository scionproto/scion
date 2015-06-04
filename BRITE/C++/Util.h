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
#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <sstream>
#include <string>
#include <math.h>
#include <fstream>
#include <new>
#include <vector>
#include <list>
#include <assert.h>

using namespace std;

#define MAXNUM 0x3FFFFFFF
#define	MAXINT	2147483647

enum Color { YELLOW, BLUE, RED, WHITE,
	     BLACK, PURPLE, CYAN, PINK, GRAY};

enum Seed {PLACES = 1, CONNECT = 2};


class RandomVariable {

 public:

  RandomVariable(unsigned short int* seed);
  ~RandomVariable();
  double GetValUniform();
  double GetValUniform(double r);
  double GetValUniform(double a, double b);
  double GetValExponential(double lambda);
  double GetValNormal(double avg, double std);
  double GetValPareto(double scale, double shape);
  double GetValLognormal(double avg, double std);
  unsigned short int GetSeed(int i) {return seed[i];}

 private:

  unsigned short int seed[3];
  unsigned short int* sptr;

};

inline double RandomVariable::GetValUniform() {

  return erand48(seed);

}

inline double RandomVariable::GetValUniform(double r) {

  return  r * erand48(seed);

}

inline double RandomVariable::GetValUniform(double min, double max) {
  return min + GetValUniform(max - min);
}

inline double RandomVariable::GetValExponential(double lambda) {
  assert(lambda > 0);
  return (-log(GetValUniform())/lambda);  
}

inline double RandomVariable::GetValPareto(double scale, double shape) {

  assert(shape > 0);
  double x = GetValUniform();
  double den = pow(1.0 - x + x*pow(1.0/scale, shape), 1.0/shape);
  double res = 1.0/den;
  return res;

}

inline double RandomVariable::GetValLognormal(double avg, double std) {
  
  return (exp(GetValNormal(avg, std))); 

}

int BinarySearch(vector<double>&, int, int, double);


#endif /* UTIL_H */

