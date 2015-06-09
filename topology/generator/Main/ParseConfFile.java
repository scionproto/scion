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

package Main;

import Model.*;
import Util.*;

import java.io.*;
import java.util.*;


/** 
 *  Functionality to import from Brite config file
 *
 *  
 */


final public class ParseConfFile {
    
    private static BufferedReader br;
    private static StreamTokenizer t;
    
    public static Model Parse(String confFile) {
      
      try { 
	    br = new BufferedReader(new FileReader(confFile));
	}
	catch (IOException e) {
	  Util.ERR("Error reading from file. ", e);
	}

	t = new BriteConfTokenizer(br);
	Model m = null;
	try {
	    while (t.ttype!=t.TT_EOF) {
		HashMap h = ParseModel();
		if (h==null && t.ttype == t.TT_EOF){
		    Util.MSG("Finished Parsing Configuration file");
		    return m;
		}
		//System.out.println(h.toString());
	        m = CreateModel(h);
		if (m==null) {
		  Util.ERR(" Could not create a model from specified model configuration. "); 
		}
	       
		return m;
	    }
	}
	catch (Exception e) {
	    Util.ERR("Error in configuration file at line: " + t.lineno()+"\n", e);
	}
	Util.MSG("Parsing of config file complete.");
	return m;
    }

    
    

    private static TopDownHierModel ParseTopDown(HashMap params) {
	Util.DEBUG("Parser found Top Down Model");
	int edgeConn =(int)  ((Double)params.get("edgeConn")).doubleValue();
	int k=-1;
	if (params.containsKey("k"))
	    k = (int)  ((Double)params.get("k")).doubleValue();
	int bwInter = (int) ((Double)params.get("BWInter")).doubleValue();
	int bwIntra = (int) ((Double)params.get("BWIntra")).doubleValue();
	float interMin =(float) ((Double)params.get("BWInterMin")).doubleValue();
	float interMax = (float) ((Double)params.get("BWInterMax")).doubleValue();
	float intraMin = (float) ((Double)params.get("BWIntraMin")).doubleValue();
	float intraMax = (float) ((Double)params.get("BWIntraMax")).doubleValue();
	
	ArrayList models = new ArrayList(2);
	HashMap p = ParseModel();
	models.add(CreateModel(p));
	HashMap p2 = ParseModel();
	
	//System.out.println(p2.toString));
	models.add(CreateModel(p2)); 
	
	return new TopDownHierModel(models, edgeConn, k, bwInter, interMin, interMax, bwIntra, intraMin, intraMax);
		
    }
    
    private static BottomUpHierModel ParseBottomUp(HashMap params) {
	Util.DEBUG("Parser found Bottom Up Model");
	int groupingMethod = (int)  ((Double)params.get("Grouping")).doubleValue();
	int assignType = (int)  ((Double)params.get("AssignType")).doubleValue();
	int numASNodes = (int)  ((Double)params.get("NumAS")).doubleValue();
	float interMin = (float) ((Double)params.get("BWInterMin")).doubleValue();
	float interMax = (float) ((Double)params.get("BWInterMax")).doubleValue();
	int bwInter = (int) ((Double)params.get("BWInter")).doubleValue();
	
	HashMap p = ParseModel();
	//System.out.println(p.toString());
	return new BottomUpHierModel(CreateModel(p), numASNodes, groupingMethod, assignType, bwInter, interMin, interMax);
    }
    
    private static FileModel ParseFileModel(HashMap params, int modelName) {
	
	int format = (int) ((Double)params.get("Format")).doubleValue();
	String file = (String) params.get("File");
	
	int HS = (int) ((Double)params.get("HS")).doubleValue();
	int LS =  (int)  ((Double)params.get("LS")).doubleValue();
	int bwDist = (int)  ((Double)params.get("BWDist")).doubleValue();
	float bwMax =(float) ((Double)params.get("BWMax")).doubleValue();
	float bwMin = (float) ((Double)params.get("BWMin")).doubleValue();
	FileModel fm = new  FileModel(format, file, modelName, HS, LS, bwDist, bwMin, bwMax);
	if (fm == null) 
	  Util.ERR("Could not create an imported file model from the configuration file. ");
	return fm;
    }
    
    
    private static Model ParseWaxman(HashMap params, int modelName) {
	int N =  (int)  ((Double)params.get("N")).doubleValue();
	int HS =  (int)  ((Double)params.get("HS")).doubleValue();
	int LS =  (int)  ((Double)params.get("LS")).doubleValue();
	int np = (int)  ((Double)params.get("NodePlacement")).doubleValue();
	int gt = (int)  ((Double)params.get("GrowthType")).doubleValue();
	int m = (int)  ((Double)params.get("m")).doubleValue();
	int bwDist = (int)  ((Double)params.get("BWDist")).doubleValue();
	float bwMax =(float) ((Double)params.get("BWMax")).doubleValue();
	float bwMin = (float) ((Double)params.get("BWMin")).doubleValue();
	float  alpha  =  (float)  ((Double)params.get("alpha")).doubleValue();
	float beta =  (float) ((Double)params.get("beta")).doubleValue();
	
	//Util.DEBUG(params.toString());
	
	if (modelName == ModelConstants.RT_WAXMAN) {
	    Util.DEBUG("Parser found Router Waxman");
	    return new  RouterWaxman(N, HS, LS, np, m, alpha, beta, gt, bwDist, bwMin, bwMax);
	}
	else if (modelName == ModelConstants.AS_WAXMAN) {
	    Util.DEBUG("Parser found AS Waxman");
	    return new  ASWaxman(N, HS, LS, np, m, alpha, beta, gt, bwDist, bwMin, bwMax);
	}
	
	Util.ERR("Error in creating model from config file, line:"+t.lineno()+" "+t.sval+"\n");
	return null;  //to make javac happy
   
    }
    
    private static Model ParseBarabasi(HashMap params, int modelName) {
	int N =  (int)  ((Double)params.get("N")).doubleValue();
	int HS =  (int)  ((Double)params.get("HS")).doubleValue();
	int LS =  (int)  ((Double)params.get("LS")).doubleValue();
	int np = (int)  ((Double)params.get("NodePlacement")).doubleValue();
	int m = (int)  ((Double)params.get("m")).doubleValue();
	int bwDist = (int)  ((Double)params.get("BWDist")).doubleValue();
	float bwMax = (float) ((Double)params.get("BWMax")).doubleValue();
	float  bwMin = (float) ((Double)params.get("BWMin")).doubleValue();
	
	if (modelName == ModelConstants.RT_BARABASI) {
	    Util.DEBUG("Parser found Router BarabasiAlbert");
	    return new RouterBarabasiAlbert(N, HS, LS, np, m, bwDist, bwMin, bwMax);
	}
	else if (modelName == ModelConstants.AS_BARABASI) {
	    Util.DEBUG("Parser found AS BarabasiAlbert");
	    return new ASBarabasiAlbert(N, HS, LS, np, m, bwDist, bwMin, bwMax);
	}
   
	else if (modelName == ModelConstants.RT_BARABASI2) {
	    Util.DEBUG("Parser found Router BarabasiAlbert2");
	    float f1 = (float) ((Double)params.get("p")).doubleValue();
	    float f2 = (float) ((Double)params.get("q")).doubleValue();
	    return new RouterBarabasiAlbert2(N, HS, LS, np, m, bwDist, bwMin, bwMax, f1, f2);
	}
	else if (modelName == ModelConstants.AS_BARABASI2) {
	    Util.DEBUG("Parser found AS BarabasiAlbert2");
	    float f1 = (float) ((Double)params.get("p")).doubleValue();
	    float f2 = (float) ((Double)params.get("q")).doubleValue();
	    return new ASBarabasiAlbert2(N, HS, LS, np, m, bwDist, bwMin, bwMax, f1, f2);
	}
	
	else if (modelName == ModelConstants.RT_GLP) {
	    Util.DEBUG("Parser found RT GLP");
	    float f1 = (float) ((Double)params.get("p")).doubleValue();
	    float f2 = (float) ((Double)params.get("beta")).doubleValue();
	    return new RouterGLP(N, HS, LS, np, m, bwDist, bwMin, bwMax, f1, f2);
	}	
	else if (modelName == ModelConstants.AS_GLP) {
	    Util.DEBUG("Parser found AS GLP");
	    float f1 = (float) ((Double)params.get("p")).doubleValue();
	    float f2 = (float) ((Double)params.get("beta")).doubleValue();
	    return new ASGLP(N, HS, LS, np, m, bwDist, bwMin, bwMax, f1, f2);
	}
	
	
	Util.ERR("Error in creating model from config file, line:"+t.lineno()+" "+t.sval+"\n");
	return null; //will never get here, but this is to make javac happy
    }

  

    private static Model CreateModel(HashMap params) {
	/*first get name*/
       
	int modelName = (int) ((Double)params.get("Name")).doubleValue();

	if (modelName == ModelConstants.RT_WAXMAN || modelName == ModelConstants.AS_WAXMAN)
	    return ParseWaxman(params, modelName);
	
	else if (modelName == ModelConstants.RT_BARABASI || modelName == ModelConstants.AS_BARABASI
		 || modelName == ModelConstants.RT_BARABASI2 || modelName == ModelConstants.AS_BARABASI2
		 || modelName == ModelConstants.RT_GLP || modelName==ModelConstants.AS_GLP)
	  return ParseBarabasi(params, modelName); 

	else if (modelName == ModelConstants.HI_TOPDOWN) 
	    return ParseTopDown(params);
       	
	else if (modelName == ModelConstants.HI_BOTTOMUP)
	  return ParseBottomUp(params);
	
	else if (modelName == ModelConstants.AS_FILE || modelName == ModelConstants.RT_FILE) //Reading from RouterFile
	  return ParseFileModel(params, modelName);
	
	Util.ERR("Error in creating model from config file, line:"+t.lineno()+" "+t.sval+"\n");
	//System.exit(0);
	return null;  //to make javac happy
    }

    public static HashSet ParseExportFormats() {
	HashSet ExportFormat = new HashSet();
	
	try {
	    while (t.ttype!=t.TT_EOF) {
		if (t.ttype == t.TT_WORD && t.sval.equals("BeginOutput"))
		    break;
		else t.nextToken();
	    }
	    if (t.ttype == t.TT_EOF) return null;
	    
	    t.nextToken();
	    while (t.ttype != t.TT_EOF) {
		if (t.ttype == t.TT_WORD && t.sval.equals("EndOutput"))
		    break;
		//Parse Key-Value pair  (one per line)
		while (t.ttype!=t.TT_EOL) {
		    String attrib="";
		    //this is the attribute
		    if (t.ttype == t.TT_WORD)
		        attrib = t.sval;
		    
		    t.nextToken(); t.nextToken();  
		    //now parse value:
		   
		    double d = (new Double(t.nval)).doubleValue();
		    if (d == 1.0)
			ExportFormat.add(attrib);
		 
		    t.nextToken();
		}
		t.nextToken();
	    }
	    t.nextToken(); //skip "EndOutput"
	}
	catch (Exception e) {
	    Util.ERR("Parser Error when parsing Export Outputs at lineno: " + t.lineno() +"\n", e);
	}
	return ExportFormat;
    }
    

    public static void close() {
	try {
	    br.close();
	}
	catch (Exception e) {
	    Util.ERR("Error closing config file. ", e);
	}
    }

    
    private static HashMap ParseModel() {
       	HashMap AttribValue = new HashMap();
	//System.out.println("DEBUG: Parsing model");
	
	try {
	    while (t.ttype!=t.TT_EOF ) {
		if (t.ttype==t.TT_WORD && t.sval.equals("BeginModel")){
		    break;
		}
		else t.nextToken();
	    }
	    if (t.ttype == t.TT_EOF) 
		return null;

	    t.nextToken();
	   
	    while (t.ttype != t.TT_EOF) {
		if (t.ttype == t.TT_WORD && t.sval.equals("EndModel"))
		    break;
		//Parse Key-Value pair  (one per line)
		while (t.ttype!=t.TT_EOL) {
		    String attrib="";
		    //this is the attribute
		    if (t.ttype == t.TT_WORD)
		        attrib = t.sval;
		   
		    t.nextToken(); t.nextToken();  
		    //now parse value:
		   
		    if (t.ttype == t.TT_WORD)
			AttribValue.put(attrib, t.sval);
		    else 
			AttribValue.put(attrib, new Double(t.nval));
		    t.nextToken();
		}
		t.nextToken();
	    }
	    t.nextToken(); //skip "EndModel"
	}
	catch (IOException e) {  
	    Util.ERR("Parse Error at lineno: " + t.lineno() +"\n", e);
	    //System.exit(0);
	}
	
	return AttribValue;
    }
		
    
}


class BriteConfTokenizer extends StreamTokenizer {

    protected BriteConfTokenizer(Reader r) {
	super(r);
	eolIsSignificant(true);
	commentChar('#');
	slashStarComments(true);
	wordChars('/', '/');   //needed for file path 
	wordChars('_', '_'); //needed for file/dir names
	wordChars('.', '.' ); //needed for dir path
    }

}










