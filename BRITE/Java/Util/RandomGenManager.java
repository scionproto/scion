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

import java.io.*;         //to import and export seeds
import java.util.*;


/**
   The RandomGenManager (short for Random Number Generator Manager)
   handles all the independent random number generator streams a Model
   may require.  Example, a Model may require a random generator for
   placing the nodes on the plane and an independent generator to
   connect the nodes, another to assign bandwidths etc.    The
   RandomGenManger also provides a parsing routine to read from a seed file
   and methods to set the seed of each random number generator stream.
   <p> Each Model has one (and only one) RandomGenManager.  See, for
   instance, Model.setRandomGenManager() method.
  */
final public class RandomGenManager {
    
    //TODO:  this is ugly. have a growable array of random generators instead!
    private  static long placeSeed, connectSeed, BWSeed, ECSeed, GroupSeed, AssignSeed;
    
    private static   Random PlaceRandom = new Random();
    private static   Random ConnectRandom = new Random();;
    private static   Random BWRandom = new Random();;
    private static   Random EdgeConnRandom = new Random();; /*these are only used by heirarchical models*/
    private static   Random GroupingRandom = new Random();;
    private static   Random AssignRandom = new Random();
    public RandomGenManager() {}

    /**
       Given a filename, parses the seeds of the various independent streams from the file.
       An example seedfile looks like: <p>
       <pre>
       PLACES 6167 34322 540141     #to place nodes on the plane
       CONNECT 4149 3274 811023     #to connect nodes 
       EDGE_CONN 4321 6394 564736   #used in the edge connection method in TopDownHier model
       GROUPING 39856 9062 30034    #used when grouping routers into an AS, in BottomUpHier model
       ASSIGNMENT 2603 24124 6350  #used in BottomUpHierModel to decide how many routers each AS gets.
       BANDWIDTH 1073 33601 47040  #used to specify bandwidth to edges in a topology
       </pre>
       <p> The divisions of three are to maintain compatability with the C++ version's erand48() call.
    */
    public void parse(String filename) {
	BufferedReader br=null;
	try {
	    br = new BufferedReader(new FileReader(new File(filename)));
	}
	catch (IOException e) { 
	    Util.ERR("Error reading seedfile. "+e);
	}

	String line="";
	try {
	    while ( (line=br.readLine())!=null) {
		StringTokenizer st = new StringTokenizer(line);
		String seedName = st.nextToken();
		String first = st.nextToken();
		String second = st.nextToken();
		String third=st.nextToken();
		String seedString = first.trim()+second.trim()+third.trim();
		long seedValue = Long.parseLong(seedString);
		if (seedName.equals("PLACES"))
		    setPlaceNodesSeed(seedValue);
		else if (seedName.equals("CONNECT"))
		    setConnectNodesSeed(seedValue);
		else if (seedName.equals("BANDWIDTH"))
		    setBWSeed(seedValue);
		else if (seedName.equals("EDGE_CONN"))
		    setEdgeConnSeed(seedValue);
		else if (seedName.equals("GROUPING"))
		    setGroupingSeed(seedValue);
		else if (seedName.equals("ASSIGNMENT"))
		    setAssignSeed(seedValue);
	    }
	}
	catch (Exception e2) {
	    Util.ERR("Error reading seedfile. "+e2);
	}
	
    }

    // Given a long seed, this method splits it into three smaller strings. 
    /*This is to maintain compatibility with erand48() and C++ version
      @param l the long seed
      @param String Three space delimited strings which when conctaneated are equal to the long seed.
    */ 
    private String longTo3String(long l) {
	String[] returnThis = new String[3];
	String longS =  Long.toString(l);
	int div = longS.length()/3;
	
	returnThis[0]=longS.substring(0, div);
	returnThis[1]=longS.substring(div, (2*div));
	returnThis[2]=longS.substring(2*div);
	
	String returnme = returnThis[0]+" " + returnThis[1]+" " + returnThis[2];
	return returnme;
    }
    
    /** Export the seeds used to lastSeedFile. (generally called "last_seed_file")
	Export the current state of the PRNG and  to nextSeedFile so the next experiement can continue to
	use the independent streams  (generally this file is called "seed_file")
    */
    public void export(String lastSeedFile, String nextSeedFile) {
	Util.MSG("exporting seedfiles..");
	BufferedWriter bw=null;
	try {
	    bw =new BufferedWriter(new FileWriter(new File(lastSeedFile)));
	    bw.write("PLACES " + longTo3String(placeSeed) + "\t# used when placing nodes on the plane");
	    bw.newLine();
	    bw.write("CONNECT "+ longTo3String(connectSeed) + "\t# used when interconnecting nodes");
	    bw.newLine();
	    bw.write("EDGE_CONN " + longTo3String(ECSeed)+"\t# used in the edge connection method of top down hier");
	    bw.newLine();
	    bw.write("GROUPING " +longTo3String(GroupSeed)+"\t# used when deciding which routers to group into an AS in bottom up hier");
	    bw.newLine();
	    bw.write("ASSIGNMENT "+longTo3String(AssignSeed)+"\t# used when deciding how many routers to group into an AS in bottom up hier");
	    bw.newLine();
	    bw.write("BANDWIDTH "+longTo3String(BWSeed)+"\t# used when assigning bandwidths");
	    bw.newLine();
	    bw.close();
	}
	catch (IOException e) {
	    System.out.println("[BRITE ERROR]: Error writing seeds to seedfile. "+e);
	}
	
	try {
	    bw = new BufferedWriter(new FileWriter(new File(nextSeedFile)));
	    bw.write("PLACES " + longTo3String(PlaceRandom.nextLong()) + "\t# used when placing nodes on the plane");
	    bw.newLine();
	    bw.write("CONNECT "+ longTo3String(ConnectRandom.nextLong()) + "\t# used when interconnecting nodes");
	    bw.newLine();
	    bw.write("EDGE_CONN " + longTo3String(EdgeConnRandom.nextLong())+"\t# used in the edge connection method of top down hier");
	    bw.newLine();
	    bw.write("GROUPING " +longTo3String(GroupingRandom.nextLong())+"\t# used when deciding which routers to group into an AS in bottom up hier");
	    bw.newLine();
	    bw.write("ASSIGNMENT "+longTo3String(AssignRandom.nextLong())+"\t# used when deciding how many routers to group into an AS in bottom up hier");
	    bw.newLine();
	    bw.write("BANDWIDTH "+longTo3String(BWRandom.nextLong())+"\t# used when assigning bandwidths");
	    bw.newLine();
	    bw.close();
	}
	catch (IOException e) {
	    System.out.println("[BRITE ERROR]: Error writing seeds to seedfile. "+e);
	}
    }
    
    
    /*get seeds*/
    public long getPlaceNodesSeed() { return placeSeed; }
    public long getConnectNodesSeed() { return connectSeed; }
    public long getBWSeed() { return BWSeed; }
    public long getEdgeConnSeed() { return ECSeed; }
    public long getGroupingSeed() { return GroupSeed; }
    public long getAssignSeed() { return AssignSeed; }
    /*get random number generators*/
    public static Random PLACE_NODES() { return PlaceRandom; }
    public static Random CONNECT_NODES() { return ConnectRandom; }
    public static Random BW() { return BWRandom; }
    public static Random EDGE_CONN() { return EdgeConnRandom; }
    public static Random GROUPING() { return GroupingRandom; }
    public static Random ASSIGN() { return AssignRandom; }


    /** set the seed for the random stream used to place nodes on the plane*/
    public void setPlaceNodesSeed(long seed) { 	
	placeSeed = seed;
	PlaceRandom.setSeed(seed); 
    }
    

    /** set the seed for the random stream used to connect nodes */
    public void setConnectNodesSeed(long seed) {
	connectSeed = seed;
	ConnectRandom.setSeed(seed);
    }

    
    /** set the seed for the random stream used to assign bandwidths to edges*/
    public void setBWSeed(long seed) {  
	BWSeed = seed;
	BWRandom.setSeed(seed);    
    }
    
    /** set the seed for the random stream used in TopDownHierModel for the Edge Connection method (i.e. connecting ASs)*/
    public void setEdgeConnSeed(long seed) {
	ECSeed = seed;
	EdgeConnRandom.setSeed(seed);
    }
    
    /** set the seed for the random stream used in BottomUpHierModel to select routers go into a specifc AS*/
    public void setGroupingSeed(long seed) {
	GroupSeed = seed;
	GroupingRandom.setSeed(seed);
    } 
    
    /** set the seed for the random stream used in BottomUpHierModel to determine how many routers are assigned to a specific AS*/
    public void setAssignSeed(long seed) {
	AssignSeed = seed;
	AssignRandom.setSeed(seed);
    }
    
  //to debug:
  
    public static void main(String args[]) {
	RandomGenManager r = new RandomGenManager();
	r.parse(args[0]);
	//	r.export(args[1]);
	r.export("last_seed_file", "next_seed_file");
	
    }
  
}














