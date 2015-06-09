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

package Model;

import java.util.Random;
import java.lang.Math;

/**
 *
 * 
 *
 */
public final class Distribution { 
    
    
    public static double getUniformRandom(Random r) {
	return r.nextDouble();
    }

    /*returns a rand between low (exclusive) and high (inclusive)*/
    public static int getUniformRandom(Random r, int low, int high) {
	int n=0;
	while (n==0) 
	    n = r.nextInt(high); /*this gives me a number between 0 and high, inclusive*/
	return n+low; /*shift*/
    }
    
    //-------------------------------- -----------------------
    public static double getGaussianRandom(Random r, double mean, double std) {
	return ( r.nextGaussian()*std+mean);
    }


    public static double getParetoRandom (Random r, double K, double P, double ALPHA) {
	
	double x = r.nextDouble();
	double    den =Math.pow(1.0-x+x*Math.pow(K/P, ALPHA), 1/ALPHA); 
	while (den==0) {
	    x = r.nextDouble();
	    den =Math.pow(1.0-x+x*Math.pow(K/P, ALPHA), 1/ALPHA); 
	}
	return (K/den);
		
    }

    public static double getParetoRandom (Random r, double scale, double shape) {
	
	double x = r.nextDouble();
	double    den =Math.pow(1.0-x+x*Math.pow(1.0/scale, shape), 1/shape); 
	while (den==0) {
	    x = r.nextDouble();
	    den =Math.pow(1.0-x+x*Math.pow(1.0/scale, shape), 1/shape); 
	}
	return (1/den);
		
    }
    
    public static double  getExponentialRandom(Random r, double lambda) {
	double u = getUniformRandom(r);
	return -(1.0/lambda)*Math.log(u);
    };
}









