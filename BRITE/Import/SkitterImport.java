package Import;

import java.io.*;
import java.lang.*;
import java.util.*;


import Topology.*;
import Model.*;
import Graph.*;
import Export.*;
import Util.*;


public class SkitterImport {
  private BufferedReader br;
  Graph g;
  HashMap ip2node;
  boolean isAS;
  
  public SkitterImport(File inFile, int type) {
    try {
      br = new BufferedReader(new FileReader(inFile));
    }
    catch (IOException e) {
      Util.ERR("Error reading from file  " + e);
    }
    if (type == ModelConstants.AS_FILE)
      isAS=true;
    else isAS=false;
    g = new Graph();
    ip2node = new HashMap();
  }
  
  private Node getNodeFromMap(String ip) {
    if (ip2node.containsKey(ip))
      return (Node) ip2node.get(ip);
    else {
      Node n = new Node();
      if (isAS) n.setNodeConf(new ASNodeConf());
      else n.setNodeConf(new RouterNodeConf());
      n.setAddr(ip);
      ip2node.put(ip,n);
      g.addNode(n);
      return n;
    }
  }
  
  private void makeEdge(String frmIP, String toIP) {
    Node frmNode = getNodeFromMap(frmIP);
    Node toNode = getNodeFromMap(toIP);
    if (!g.hasEdge(frmNode, toNode)) {
      Edge e = new Edge(frmNode, toNode);
      e.setDirection(GraphConstants.DIRECTED);
      g.addEdge(e);
    }
    
  }

  public void convert(String briteFile) {
    Graph g = parse();
    Topology t = new Topology(g);
    BriteExport be = new BriteExport(t, new File(briteFile));
    be.export();
  }
  
  public Graph parse() {
    String line="";
    int paths=0;
    try {
      while ( (line=br.readLine())!=null) {
	if ( (line.trim().startsWith("#")) || line.trim().equals("")) continue;
	StringTokenizer st = new StringTokenizer(line);
	String stat = st.nextToken();
	String src = st.nextToken();
	String dst = st.nextToken();
	st.nextToken(); st.nextToken();
	if (!st.hasMoreTokens()) continue;
	String frmIP = st.nextToken();
	makeEdge(src, frmIP); //connect src to first hop
	while (st.hasMoreTokens()) {
	  String toIP = st.nextToken();
	  makeEdge(frmIP, toIP);
	  frmIP = toIP;
	}
	if (stat.equals("C")) makeEdge(frmIP, dst);
	++paths;
	if (paths%1000==0) System.out.print(".");
      }
      Util.MSG("created graph from skitter file,  |V| = " + g.getNumNodes()+ " and |E| = " + g.getNumEdges());
    }
    catch (IOException e) {
      Util.ERR("Error building graph from Skitter file.", e);
    }
    return g;
  }
    
  //todebug:
  public static void main(String args[]) throws Exception {
    String fileToRead="";
    String fileToWrite="";
    String asOrRouter="";
    try {
      fileToRead= args[0];
      fileToWrite=args[1];
      asOrRouter=args[2];
    }
    catch (Exception e) {
      Util.ERR("usage:  java Import.SkitterImport <artsdump-file> <output-filename>  RT {|AS}");
    }
    
    Util.MSG("Importing Skitter ..");
    FileModel f;
    if (asOrRouter.equals("AS"))
      f = new FileModel(ImportConstants.SKITTER_FORMAT, fileToRead, ModelConstants.AS_FILE);
    else
      f = new FileModel(ImportConstants.SKITTER_FORMAT, fileToRead, ModelConstants.RT_FILE);
    
    Topology t = new Topology(f);
    Util.MSG("Writing to BRITE format ..");
    BriteExport be = new BriteExport(t, new File(fileToWrite));
    be.export();

  }

}



class NodeAddrComparator implements Comparator {
  public int compare(Object n1, Object n2) {
    String n1addr = ((Node)n1).getAddrS();
    String n2addr = ((Node)n2).getAddrS();
	
    return n1addr.compareTo(n2addr);
  }
}
