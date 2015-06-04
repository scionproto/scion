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

package Util;


import java.lang.Exception;

/**
   A repository of miscellaneous utility functions.
 */
public final class Util {

    /** given two int a<2^16 and b<2^16, encode returns a
	non-commuatative encoding of a and b.  this is a handy little
	encoding function to group two small integers into a single
	32bit integer. an example of its use can be found in the
	collision detection code in RouterModel.placeNodes() 
	
	@param a  integer < 2^16
	@param b integer < 2^16
	@return int encoding of a,b
    */
    public static int Encode(int a, int b) {
	//WARNING: only works with a<2^16 && b<2^16
	//WARNING2:  Not commutative.  That is: e(a,b)!=e(b,a)
	return ( (a<<16)|b);
    }

    
    /**Print an error formatted string and exit app*/
    public static void ERR(String err) {
	System.out.println("[ERROR]  : " + err);
	System.exit(0);
    }
  
  /** print an error message and stack trace and exit*/
  public static void ERR(String err, Exception e ) {//throws Exception {
    System.out.println("[ERROR]  : " + err);
    e.printStackTrace();
    //throw e; 
    System.exit(0);
    
  }
    
    /** print a debug formatted string */
    public static void DEBUG(String debug) {
	System.out.println("[DEBUG]  : " + debug);
    }
    
    /** print a message formatted string*/
    public static void MSG(String msg) {
	System.out.println("[MESSAGE]: " + msg);
    }

    /** print a message formatted string but without an EOL character */
    public static void MSGN(String msg) {
	System.out.print("[MESSAGE]: " + msg+"  ");
    }

  /** assert some boolean condition, ala C++.  Thanks to stanrost@mit.edu*/
    /*public static void assert(boolean exp)  {
      assert(exp, new String(""));
      }
    */
  /** assert some boolean condition ala C++.  Thanks to stanrost@mit.edu */
    /*public static  void assert(boolean exp, String explain)   {
      if (exp == false)      {
      try {
      throw new Exception(explain);
      } 
      catch (Exception e)  {
      Util.ERR("Assertion ("+explain+") failed.", e);
      }
      }
    */
}








