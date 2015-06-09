package Import;

import java.io.*;
import java.util.*;
import java.lang.*;

import Graph.*;
import Util.*;
import Topology.*;
import Model.*;
import Export.*;

public class SCANImport {
    BufferedReader br;
    Graph g;
    private HashMap id2node;
    private boolean isAS;
  
  public SCANImport(File f, int type) {
    try {
      br = new BufferedReader(new FileReader(f));
    }
    catch (IOException e) {
      Util.ERR("Exception in reading from file", e);
    }
    if (type == ModelConstants.AS_FILE)
      isAS=true;
    else isAS=false;
    g=new Graph();
    id2node = new HashMap();
  }
  
  
  /*
    file looks like this:

    R192412 :  R66670 R34033 R21369 R65000 R131113 R193792 R131112 R193791 R244988
    R258023 :  R18441
  */
  
  private Node getNodeFromID(String id) {
    if (id2node.containsKey(id)) {
      return (Node) id2node.get(id);
    }
    Node n = new Node();
    if (isAS) n.setNodeConf(new ASNodeConf());
    else n.setNodeConf(new RouterNodeConf());
    g.addNode(n);
    n.setAddr(id);
    id2node.put(id, n);
    return n;
  }
  
  public Graph parse() {
      Util.MSG("parsing anonymized scan file");
      String line="";
      try {
	while ((line=br.readLine())!=null) {
	  StringTokenizer st = new StringTokenizer(line);
	  String src = st.nextToken();
	  Node srcNode =getNodeFromID(src);
	  st.nextToken(); //skip :
	  while (st.hasMoreTokens()) {
	    String dst = st.nextToken();
	    Node dstNode = getNodeFromID(dst);
	    Edge e = new Edge(srcNode, dstNode);
	    g.addEdge(e);
	  }
	}
      }
      catch (Exception e) {
	Util.ERR("Error building graph from SCAN file.", e);
      }
      
      Util.MSG("created graph from SCAN file,  |V| = " + g.getNumNodes()+ " and |E| = " + g.getNumEdges());
      return g;
    }
  

  public void convert(String briteFile) {
    Graph g = parse();
    Topology t = new Topology(g);
    BriteExport be = new BriteExport(t, new File(briteFile));
    be.export();

  }
  
    public static void main(String args[]) {
      String fileToRead="";
      String fileToWrite="";
      String asOrRouter="";
      try {
	fileToRead= args[0];
	fileToWrite=args[1];
	asOrRouter=args[2];
      }
      catch (Exception e) {
	Util.ERR("usage:  java Import.SCANImport <scan-file> <output-filename>  RT {|AS}");
	
      }
      
      Util.MSG("Importing SCAN file ..");
      FileModel f;
      if (asOrRouter.equals("AS"))
	f = new FileModel(ImportConstants.SCAN_FORMAT, fileToRead, ModelConstants.AS_FILE);
      else 
	f = new FileModel(ImportConstants.SCAN_FORMAT, fileToRead, ModelConstants.RT_FILE);
      
      Topology t = new Topology(f);
      Util.MSG("Writing to BRITE format ..");
      BriteExport be = new BriteExport(t, new File(fileToWrite));
      be.export();
      
    }
  


}



