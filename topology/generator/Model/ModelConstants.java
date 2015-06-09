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

/**
   All constants pertaining to a Model are stored here for convenient
   access.  Similar classes exist for Graph, Import etc. */

final public class ModelConstants {
   
    
    /*Model Types*/
  public static int RT_WAXMAN=1;
  public static int RT_BARABASI =2;
  public static int AS_WAXMAN = 3;
  public static int AS_BARABASI=4;
  public static int HI_TOPDOWN = 5;
  public static int HI_BOTTOMUP = 6;
  public static int RT_FILE = 7;
  public static int AS_FILE = 8;
  
  public static int RT_BARABASI2 = 9;
  public static int AS_BARABASI2 = 10;
  public static int RT_GLP = 11;
  public static int AS_GLP = 12;
  
  /*Node Placement*/
    public static int NP_RANDOM = 1; 
    public static int NP_HEAVYTAILED = 2;

    /*Growth type*/
    public static int GT_INCREMENTAL = 1;
    public static int GT_ALL = 2;
    
    /*Pref Type*/
    public static int PC_NONE = 1;
    public static int PC_BARABASI=2;

    /*Conn. Locality*/
    public static int CL_ON=1;
    public static int CL_OFF=2;
    
    /*Top Down Model Edge Connection Methods*/
    public static int TD_RANDOM=1;
  public static int TD_SMALLEST = 2;          //connect smallest degree
  public static int TD_SMALLEST_NONLEAF = 3;  //connect smallest degree nonleaf
  public static int TD_KDEGREE = 4;

    /*Bottom Up*/
    public static int BU_RANDOMPICK = 1;
    public static int BU_RANDOMWALK = 2;

    public static int BU_ASSIGN_CONST = 1;
    public static int BU_ASSIGN_UNIFORM = 2;
    public static int BU_ASSIGN_HT = 3;
    public static int BU_ASSIGN_EXP = 4;

    /*Bandwidth*/
    public static int BW_CONSTANT = 1;
    public static int BW_UNIFORM = 2;
    public static int BW_HEAVYTAILED = 3;
  public static int BW_EXPONENTIAL = 4;

    /*Delay */

    /*---------------------------------------------------------------------*/
    
    /*Node Types*/
    public static int AS_NODE = 1;
    public static int RT_NODE = 2;

    /*Router Types*/
    public static int RT_LEAF = 3;
    public static int RT_BORDER=4;
    public static int RT_STUB = 5;
    public static int RT_BACKBONE = 6;

    /*AS Types*/
    public static int AS_STUB = 7;
    public static int AS_BACKBONE = 8;
    public static int AS_LEAF = 9;
    public static int AS_BORDER = 10;
    
    
  /*Edge Types*/
  public static int E_AS = 12;
  public static int E_RT = 13;
      
  /*router edge type*/
  public static int E_RT_STUB = 16;
  public static int E_RT_BORDER = 17;
  public static int E_RT_BACKBONE = 18;
  
  /*as edge types*/
  public static int E_AS_STUB = 19;   // a stub AS edge
  public static int E_AS_BORDER = 20;  //a border AS edge
  public static int E_AS_BACKBONE = 21; //a backbone AS edge

      
    public static int NONE = 100;
}








