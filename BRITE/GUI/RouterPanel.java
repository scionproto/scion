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
/*  Author:     Anukool Lakhina                                             */
/*              Alberto Medina                                              */
/*  Title:     BRITE: Boston university Representative Topology gEnerator   */
/*  Revision:  2.0         4/02/2001                                        */
/****************************************************************************/
package GUI;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import java.io.*;           


public final class RouterPanel extends JPanel  implements ActionListener {
  
  int bwDist = -1;
  double bwMax  = -1.0;
  double bwMin = -1.0;
  boolean needConvert=false;
  String convertFilename="";

    public RouterPanel() { super(); this.init();}
    
    void EnableComponents(boolean b) {
	//enable or disable all components
	for (int i=0; i<this.getComponentCount(); ++i) {
	    Component c = this.getComponent(i);
	    c.setEnabled(b);
	}
	//but, keep ConnLocality disabled
	clComboBox.setEnabled(false);
	JLabel39.setEnabled(false);
	//and keep gamma disabled
	rtGamma.setEnabled(false);
	JLabel13.setEnabled(false);
    }
    
        
    /************* Genereate Config File Routines  ************************/
    
    private double getNumFromTextField(JTextField c, double defVal) {
	if (!c.isEnabled())
	    return -1;
	String nstr = c.getText();
	Double n=new Double(defVal);
	try {
	    n = new Double(nstr);
	} 
	catch (Exception e) { 
	    System.out.println("error in getNumFromTextField, nstr="+nstr+"  , exception=" + e);
	    return -1; /*err*/
	}
	return n.doubleValue();
    }
    
    
    public void WriteConf(BufferedWriter bw) {
      
	bwMin = getNumFromTextField(rtBWMin, 1);
	 bwMax = getNumFromTextField(rtBWMax, 1024);
	String  bwDistStr = (String) rtBWDist.getSelectedItem();
	bwDist=1;  //initialize to constant
	if (bwDistStr.equals(BW_UNIFORM))
	    bwDist=2;
	else if (bwDistStr.equals(BW_EXPONENTIAL))
	    bwDist=4;
	else if (bwDistStr.equals(BW_HEAVYTAILED))
	    bwDist=3;

      if (isReadFromFile) { 
	    WriteFileConf(bw);
	    return; 
	}
	String modelType = (String) ModelType.getSelectedItem();
	if (modelType.equals(RT_WAXMAN)) 
	    WriteWaxmanConf(bw);
	else if (modelType.equals(RT_BARABASI) || 
		 modelType.equals(RT_BARABASI2) ||
		 modelType.equals(RT_GLP))
	    WriteBarabasiConf(bw);
    }

    public void WriteConf(BufferedWriter bw, int bwDistp, double bwMinp, double bwMaxp) {
	bwDist = bwDistp;
	bwMin = bwMinp;
	bwMax = bwMaxp;
	
	if (isReadFromFile) { 
	  WriteFileConf(bw);
	    return; 
	}
	String modelType = (String) ModelType.getSelectedItem();
	if (modelType.equals(RT_WAXMAN)) 
	    WriteWaxmanConf(bw);
	else if (modelType.equals(RT_BARABASI) || 
		 modelType.equals(RT_BARABASI2) ||
		 modelType.equals(RT_GLP))
	    WriteBarabasiConf(bw);
    }
  

    private String getExt(String s) {
	String ext = null;
	int i = s.lastIndexOf('.');
	if (i>0 && i<s.length() -1)
	    ext = s.substring(i+1);
	return ext;
    }
    
  
 /** converts import format to brite format and returns name of new file. */
  public void ConvertFileToBriteFormat() {
    String extFormat = getExt(file);
    if (extFormat.equals("brite")) return ;
    
    Util.Util.MSG("Converting Router-level import file to BRITE..");
    
    String briteFile=file+".brite";
    if (extFormat.equals("nlanr")) {
	Import.NLANRImport im = new Import.NLANRImport(new File(convertFilename), Model.ModelConstants.RT_FILE);
	im.convert(briteFile);
    }
    else   if (extFormat.equals("gtitm")) {
      Import.GTImport im = new Import.GTImport(new File(convertFilename), Model.ModelConstants.RT_FILE);
      im.convert(briteFile);
    }    
    else if (extFormat.equals("gtts")) {
      Import.GTTSImport im = new Import.GTTSImport(new File(convertFilename));
      im.convert(briteFile);
    }
    else if (extFormat.equals("skitter")) {
      Import.SkitterImport im = new Import.SkitterImport(new File(convertFilename), Model.ModelConstants.RT_FILE);
      im.convert(briteFile);
    }
    else if (extFormat.equals("inet")) {
      Import.InetImport im = new Import.InetImport(new File(convertFilename), Model.ModelConstants.RT_FILE);
      im.convert(briteFile);
    }   
    else if (extFormat.equals("scan")) {
      Import.SCANImport im = new Import.SCANImport(new File(convertFilename), Model.ModelConstants.RT_FILE);
      im.convert(briteFile);
    }   
    else {
	JOptionPane.showMessageDialog(this, "Converter for Extension Format " + extFormat+" not found.  ");
	needConvert=false;
	return;
    }

    needConvert=false;
  }

  
    private void WriteFileConf(BufferedWriter bw) {
	int HS = (int) getNumFromTextField(rtHS, 1000);
	int LS = (int) getNumFromTextField(rtLS, 100);
	int N = (int) getNumFromTextField(rtN, 10000);

	//determine format of input file
	int format=1;
	String extFormat = getExt(file);
	if (extFormat.equals("brite"))	    
	  format = 1;
	else {
	  needConvert=true; 	
	  convertFilename=file;
	  file = file+".brite";
	}
	
	try {	
	  bw.write("BeginModel");	                
	  bw.newLine();
	  bw.write("\tName = 7\t\t #AS File = 8, Router File = 7");                
	  bw.newLine();	
	  bw.write("\tFormat = " + format  + "\t\t #BRITE=1, GT-ITM=2, NLANR=3, SCAN=4, GT-ITM(TS)=5, Inet=6, Skitter=7");
	  bw.newLine();
	  bw.write("\tFile = " + file);
	  bw.newLine();
	  bw.write("\tHS = " + HS+"\t\t #Length of main plane (number of unit squares)");               
	  bw.newLine();
	  bw.write("\tLS = " + LS+"\t\t #Length of inner planes (number of unit squares)");              
	  bw.newLine();
	  bw.write("\tBWDist = " + bwDist+"\t\t #Constant = 1, Uniform =2, HeavyTailed = 3, Exponential =4");      
	  bw.newLine();
	  bw.write("\tBWMin = " + bwMin);         
	  bw.newLine();
	  bw.write("\tBWMax = " + bwMax);         
	  bw.newLine();
	  bw.write("EndModel");
	}
	catch (IOException e) {
	  System.out.println("[BRITE ERROR]: Could not create config file. " + e);
	  System.exit(0);
	}
    }
    
    private void WriteWaxmanConf(BufferedWriter bw) {
	/*TextField vals*/
	double alpha = getNumFromTextField(rtAlpha, 0.15);
	double beta = getNumFromTextField(rtBeta, 0.2);
	int m = (int) getNumFromTextField(rtM, 2);
	int HS = (int) getNumFromTextField(rtHS, 1000);
	int LS = (int) getNumFromTextField(rtLS, 100);
	int N = (int) getNumFromTextField(rtN, 10000);
	/*ComboBox vals*/
	String nodePlacement = (String) npComboBox.getSelectedItem();
	int np = 1;
	if (nodePlacement.equals(NP_HEAVYTAILED))
	    np =2;
	String growthType = (String) gtComboBox.getSelectedItem();
	int gt = 1;
	if (growthType.equals(GT_ALL))
	    gt = 2;

	System.out.println("in rtwaxman, reporting bw: " + bwDist+" " + bwMin+" " + bwMax);
	try {	
	    bw.write("BeginModel");	                
	    bw.newLine();
	    bw.write("\tName =  1\t\t #Router Waxman=1, AS Waxman =3");                
	    bw.newLine();
	    bw.write("\tN = "+N+"\t\t #Number of nodes in graph"); 	                
	    bw.newLine();
	    bw.write("\tHS = " + HS+"\t\t #Size of main plane (number of squares)");               
	    bw.newLine();
	    bw.write("\tLS = " + LS+"\t\t #Size of inner planes (number of squares)");              
	    bw.newLine();
	    bw.write("\tNodePlacement = " + np+"\t #Random = 1, Heavy Tailed = 2"); 	
	    bw.newLine();
	    bw.write("\tGrowthType = " + gt+"\t\t #Incremental = 1, All = 2"); 	        
	    bw.newLine();
	    bw.write("\tm = "+m+"\t\t\t #Number of neighboring node each new node connects to.");                   
	    bw.newLine();
	    bw.write("\talpha = " + alpha+"\t\t #Waxman Parameter"); 	
	    bw.newLine();
	    bw.write("\tbeta = " + beta+"\t\t #Waxman Parameter");           
	    bw.newLine();
	    bw.write("\tBWDist = " + bwDist+"\t\t #Constant = 1, Uniform =2, HeavyTailed = 3, Exponential =4");      
	    bw.newLine();
	    bw.write("\tBWMin = " + bwMin);         
	    bw.newLine();
	    bw.write("\tBWMax = " + bwMax);         
	    bw.newLine();
	    bw.write("EndModel"); bw.newLine();
	    
	}    
	catch (IOException e) {
	    System.out.println("[BRITE ERROR]: Could not create config file. " + e);
	    System.exit(0);
	}
	
	
    }
    


    void EnableBW(boolean b) {
	BWLabel.setEnabled(b);
	rtBWDist.setEnabled(b);
	BWMaxLabel.setEnabled(b);
	BWMinLabel.setEnabled(b);
	rtBWMax.setEnabled(b);
	rtBWMin.setEnabled(b);
    }


    private void WriteBarabasiConf(BufferedWriter bw) {
	/*TextField vals*/
	int m = (int) getNumFromTextField(rtM, 2);
	int HS = (int) getNumFromTextField(rtHS, 1000);
	int LS = (int) getNumFromTextField(rtLS, 100);
	int N = (int) getNumFromTextField(rtN, 10000);
	/*ComboBox vals*/
	String nodePlacement = (String) npComboBox.getSelectedItem();
	int np = 1;
	if (nodePlacement.equals(NP_HEAVYTAILED))
	    np =2;
	
	if (nodePlacement.equals(NP_HEAVYTAILED))
	    np =2;

	boolean isBA=false;
	boolean isBA2 = false;
	boolean isGLP = false;
	String model = (String) ModelType.getSelectedItem();
	double p=0.6;
	double q=0.2;
	double beta=0.1;
	if (model.equals(RT_BARABASI2)) {
	    isBA2 = true;
	    p= getNumFromTextField(rtAlpha, 0.6);
	    q = getNumFromTextField(rtBeta, 0.2);
	}
	if (model.equals(RT_GLP)) {
	    isGLP = true;
	    p= getNumFromTextField(rtAlpha, 0.6);
	    beta = getNumFromTextField(rtBeta, 0.2);
	}
	else 
	    isBA=true;
	
	try {	
	    bw.write("BeginModel");	                
	    bw.newLine();
	    if (isBA2)
	      bw.write("\tName =  9\t\t #Router Barabasi-Albert2=9, AS Barabasi-Albert2=10");                
	    else if (isGLP)
		bw.write("\t Name=11 \t\t #Router GLP=11, AS GLP=12");
	    else
		bw.write("\tName =  2\t\t #Router Barabasi-Albert=2, AS Barabasi-Albert=4");                 
	    bw.newLine();
	    bw.write("\tN = "+N+"\t\t #Number of nodes in graph"); 	                
	    bw.newLine();
	    bw.write("\tHS = " + HS+"\t\t #Size of main plane (number of squares)");               
	    bw.newLine();
	    bw.write("\tLS = " + LS+"\t\t #Size of inner planes (number of squares)");              
	    bw.newLine();
	    bw.write("\tNodePlacement = " + np+"\t\t #Random = 1, Heavy Tailed = 2"); 	
	    bw.newLine();
	    bw.write("\tm = "+m+"\t\t\t #Number of neighboring node each new node connects to.");                   
	    bw.newLine();
	    bw.write("\tBWDist = " + bwDist+"\t\t #Constant = 1, Uniform =2, HeavyTailed = 3, Exponential =4");      
	    bw.newLine();
	    bw.write("\tBWMin = " + bwMin);         
	    bw.newLine();
	    bw.write("\tBWMax = " + bwMax);         
	    bw.newLine();
	    if (isBA2) {
	      bw.write("\t p = " +p+"\t\t #Probability of adding links");
	      bw.newLine();
	      bw.write("\t q = " + q+"\t\t #Probability of rewiring links");
	      bw.newLine();
	    }
	    else if (isGLP) {
		bw.write("\t p = " +p+"\t\t #Probability of adding links");
		bw.newLine();
		bw.write("\t beta = " + beta+"\t\t #linear shift");
		bw.newLine();
	    }
	    
	    bw.write("EndModel"); bw.newLine();
	}    
	catch (IOException e) {
	    System.out.println("[BRITE ERROR]: Could not create config file. " + e);
	    System.exit(0);
	}
	
    }
    
    
    public void actionPerformed(ActionEvent e) { 
	if (e.getSource().equals(ImportRouterTopology)){
	    fc = new JFileChooser("");
	    fc.addChoosableFileFilter(TopologyFilter.brite);
	    fc.addChoosableFileFilter(TopologyFilter.gtitm);
	    fc.addChoosableFileFilter(TopologyFilter.gtts);
	    fc.addChoosableFileFilter(TopologyFilter.inet);
	    fc.addChoosableFileFilter(TopologyFilter.nlanr);
	    fc.addChoosableFileFilter(TopologyFilter.skitter);
	    fc.addChoosableFileFilter(TopologyFilter.scan);

	    fc.addActionListener(this);
	    //fc.setAcceptAllFileFilterUsed(false);
	    fc.setSize(fc.getPreferredSize());
	   
	    try {
		int ret = fc.showOpenDialog(this);
		File f = fc.getSelectedFile();
		file = f.getPath();
		RouterFileBeingReadLabel.setText("Import from file: "+ f.getName());
		isReadFromFile = true;
		RouterFileBeingReadLabel.setVisible(true);
	    }
	    catch (Exception fe) {}
	}
	else if (e.getSource().equals(ModelType)) {
	    RouterFileBeingReadLabel.setVisible(false);
	    String model = (String) ModelType.getSelectedItem();
	    if (model.equals(RT_WAXMAN)){
		npComboBox.setSelectedIndex(0);     /*RANDOM*/
		gtComboBox.setSelectedIndex(1);     /*INCREMENTAL*/
		clComboBox.setSelectedIndex(1);     /*OFF*/
		pcComboBox.setSelectedIndex(0);     /*NONE*/
		rtAlpha.setEnabled(true);
		JLabel11.setEnabled(true);
		JLabel11.setText("alpha:");
		rtAlpha.setText("0.15");
		JLabel12.setEnabled(true);
		JLabel12.setText("beta:");
		rtBeta.setEnabled(true);
		rtBeta.setText("0.2");
		rtM.setText("2"); 
		rtGamma.setText("NA");
		JLabel13.setEnabled(false);
		rtGamma.setEnabled(false);
	    }
	    else if (model.equals(RT_BARABASI)) {
		npComboBox.setSelectedIndex(0);     /*RANDOM*/
		gtComboBox.setSelectedIndex(1);     /*INCREMENTAL*/
		clComboBox.setSelectedIndex(1);     /*OFF*/
		pcComboBox.setSelectedIndex(0);     /*NONE*/
		rtAlpha.setText("NA");
		rtBeta.setText("NA");
		rtGamma.setText("NA");
		JLabel11.setText("alpha:");
		JLabel12.setText("beta:");
		JLabel11.setEnabled(false);
		JLabel12.setEnabled(false);
		JLabel13.setEnabled(false);
		rtAlpha.setEnabled(false); /*BARABASI does not take alpha,beta,gamma*/
		rtBeta.setEnabled(false);
		rtGamma.setEnabled(false);
		rtM.setText("2");
	    }
	    else if (model.equals(RT_BARABASI2)) {
	      npComboBox.setSelectedIndex(0);     /*RANDOM*/
	      gtComboBox.setSelectedIndex(1);     /*INCREMENTAL*/
	      clComboBox.setSelectedIndex(1);     /*OFF*/
	      pcComboBox.setSelectedIndex(0);     /*NONE*/
	      rtAlpha.setText("0.25");
	      rtBeta.setText("0.5");
	      rtGamma.setText("NA");
	      JLabel11.setText("p (add):");
	      JLabel11.setEnabled(true);
	      JLabel12.setEnabled(true);
	      JLabel12.setText("q (rewire):");
	      JLabel13.setEnabled(false);
	      rtAlpha.setEnabled(true); /*BARABASI2 does not take alpha,beta,gamma*/
	      rtBeta.setEnabled(true);
	      rtGamma.setEnabled(false);
	      rtM.setText("2");
	    }
	    else if (model.equals(RT_GLP)) {
	      npComboBox.setSelectedIndex(0);     /*RANDOM*/
	      gtComboBox.setSelectedIndex(1);     /*INCREMENTAL*/
	      clComboBox.setSelectedIndex(1);     /*OFF*/
	      pcComboBox.setSelectedIndex(0);     /*NONE*/
	      rtAlpha.setText("0.45");
	      rtBeta.setText("0.64");
	      rtGamma.setText("NA");
	      JLabel11.setText("p (add):");
	      JLabel11.setEnabled(true);
	      JLabel12.setEnabled(true);
	      JLabel12.setText("beta:");
	      JLabel13.setEnabled(false);
	      rtAlpha.setEnabled(true); /*BARABASI2 does not take alpha,beta,gamma*/
	      rtBeta.setEnabled(true);
	      rtGamma.setEnabled(false);
	      rtM.setText("1");
	    }
	}
    }
    
    
    void init() {
	this.setBorder(etchedBorder1);
	this.setLayout(null);
	this.setBackground(new java.awt.Color(204,204,204));
	this.setBounds(2,24,427,261);
	JLabel2.setText("Router Topology Parameters");
	JLabel2.setDoubleBuffered(true);
	this.add(JLabel2);
	JLabel2.setForeground(java.awt.Color.black);
	JLabel2.setFont(new Font("SansSerif", Font.BOLD, 12));
	JLabel2.setBounds(12,12,228,16);
	JLabel3.setText("HS:");
	JLabel3.setDoubleBuffered(true);
	this.add(JLabel3);
	JLabel3.setForeground(java.awt.Color.black);
	JLabel3.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel3.setBounds(24,48,36,21);
	JLabel4.setText("LS:");
	JLabel4.setDoubleBuffered(true);
	this.add(JLabel4);
	JLabel4.setForeground(java.awt.Color.black);
	JLabel4.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel4.setBounds(24,72,36,21);
	JLabel5.setText("N:");
       	JLabel5.setDoubleBuffered(true);
	this.add(JLabel5);
	JLabel5.setForeground(java.awt.Color.black);
	JLabel5.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel5.setBounds(156,48,36,21);
	JLabel6.setText("Model:");
	JLabel6.setDoubleBuffered(true);
	this.add(JLabel6);
	JLabel6.setForeground(java.awt.Color.black);
	JLabel6.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel6.setBounds(156,72,48,21);
	JLabel7.setText("Model Specific Parameters");
	JLabel7.setDoubleBuffered(true);
	this.add(JLabel7);
	JLabel7.setForeground(java.awt.Color.black);
	JLabel7.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel7.setBounds(12,108,204,16);
	JLabel11.setText("alpha:");
	JLabel11.setDoubleBuffered(true);
	this.add(JLabel11);
	JLabel11.setForeground(java.awt.Color.black);
	JLabel11.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel11.setBounds(288,132,55,21);
	JLabel12.setText("beta:");
	JLabel12.setDoubleBuffered(true);
	this.add(JLabel12);
	JLabel12.setForeground(java.awt.Color.black);
	JLabel12.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel12.setBounds(288,156,55,21);
	JLabel13.setText("gamma:");
	JLabel13.setDoubleBuffered(true);

	this.add(JLabel13);
	JLabel13.setForeground(java.awt.Color.black);
	JLabel13.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel13.setBounds(288,180,55,21);
	JLabel14.setText("m:");
	JLabel14.setDoubleBuffered(true);
	this.add(JLabel14);
	JLabel14.setForeground(java.awt.Color.black);
	JLabel14.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel14.setBounds(288,204,55,21);
	rtAlpha.setBorder(lineBorder1);
	rtAlpha.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtAlpha);
	rtAlpha.setBounds(360,132,46,18);
	rtBeta.setBorder(lineBorder1);
	rtBeta.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtBeta);
	rtBeta.setBounds(360,156,46,18);
	rtGamma.setBorder(lineBorder1);
	rtGamma.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));

	this.add(rtGamma);
	rtGamma.setBounds(360,180,46,18);
	rtM.setBorder(lineBorder1);
	rtM.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtM);
	rtM.setBounds(360,204,46,18);
	rtHS.setBorder(lineBorder1);
	rtHS.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtHS);
	rtHS.setBounds(60,48,46,18);
	rtHS.setText("1000");
	rtLS.setBorder(lineBorder1);
	rtLS.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtLS);
	rtLS.setText("100");
	rtLS.setBounds(60,72,46,18);
	rtN.setBorder(lineBorder1);
	rtN.setText("10000");
	rtN.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtN);
	rtN.setBounds(204,48,50,18);
	this.add(ModelType);
	ModelType.setFont(new Font("SansSerif", Font.PLAIN, 12));
	ModelType.setBounds(204,72,108,24);
	ModelType.addActionListener(this);
	this.add(RouterFileBeingReadLabel);
	RouterFileBeingReadLabel.setForeground(java.awt.Color.black);
	RouterFileBeingReadLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
	RouterFileBeingReadLabel.setBounds(10,257,396,17);
	RouterFileBeingReadLabel.setVisible(false);
	JLabel36.setText("Node Placement:");
	JLabel36.setDoubleBuffered(true);
	this.add(JLabel36);
	JLabel36.setForeground(java.awt.Color.black);
	JLabel36.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel36.setBounds(24,132,108,21);
	JLabel37.setText("Growth Type:");
	JLabel37.setDoubleBuffered(true);
	this.add(JLabel37);
	JLabel37.setForeground(java.awt.Color.black);
	JLabel37.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel37.setBounds(24,156,108,21);
	JLabel38.setText("Pref. Conn:");
	JLabel38.setDoubleBuffered(true);
	this.add(JLabel38);
	JLabel38.setForeground(java.awt.Color.black);
	JLabel38.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel38.setBounds(24,180,108,21);
	JLabel39.setText("Conn. Locality:");
	JLabel39.setDoubleBuffered(true);
	JLabel39.setEnabled(false);
	this.add(JLabel39);
	JLabel39.setForeground(java.awt.Color.black);
	JLabel39.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel39.setBounds(24,204,108,21);

	this.add(clComboBox);
	clComboBox.setFont(new Font("SansSerif", Font.PLAIN, 12));
	clComboBox.setBounds(144,204,120,24);
	clComboBox.setEnabled(false);
	
	this.add(pcComboBox);
	pcComboBox.setFont(new Font("SansSerif", Font.PLAIN, 12));
	pcComboBox.setBounds(144,180,120,24);
	this.add(gtComboBox);
	gtComboBox.setFont(new Font("SansSerif", Font.PLAIN, 12));
	gtComboBox.setBounds(144,156,120,24);
	this.add(npComboBox);
	npComboBox.setFont(new Font("SansSerif", Font.PLAIN, 12));
	npComboBox.setBounds(144,132,120,24);
	ImportRouterTopology.setHorizontalTextPosition(SwingConstants.RIGHT);
	ImportRouterTopology.setHorizontalAlignment(SwingConstants.RIGHT);
	ImportRouterTopology.setText("Import...");
	ImportRouterTopology.setActionCommand("Browse...");
	this.add(ImportRouterTopology);
	ImportRouterTopology.setFont(new Font("SansSerif", Font.PLAIN, 12));
	ImportRouterTopology.setBounds(298,12,122,19);
	ImportRouterTopology.addActionListener(this);
	
	//bandwidth stuff
	BWLabel.setText("Bandwidth Distr:");
	this.add(BWLabel);
	BWLabel.setForeground(java.awt.Color.black);
	BWLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	BWLabel.setBounds(24, 228, 108, 21);
	this.add(rtBWDist);
	rtBWDist.setFont(new Font("SansSerif", Font.PLAIN, 12));
	rtBWDist.setBounds(144,228,120,24);
	BWMaxLabel.setText("Max BW:");
	this.add(BWMaxLabel);
	BWMaxLabel.setForeground(java.awt.Color.black);
	BWMaxLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	BWMaxLabel.setBounds(288,228, 55, 21);
	BWMinLabel.setText("Min BW:");
	this.add(BWMinLabel);
	BWMinLabel.setForeground(java.awt.Color.black);
	BWMinLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	BWMinLabel.setBounds(288,251,  55, 21);
	rtBWMax.setBorder(lineBorder1);
	rtBWMax.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtBWMax);
	rtBWMax.setBounds(360,228,46,18);
	rtBWMin.setBorder(lineBorder1);
	rtBWMin.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(rtBWMin);
	rtBWMin.setBounds(360,252,46,18);
	
	/*for Waxman - since this is default model*/
	npComboBox.setSelectedIndex(0);     /*RANDOM*/
	gtComboBox.setSelectedIndex(1); /*INCREMENTAL*/
	clComboBox.setSelectedIndex(0); /*OFF*/
	pcComboBox.setSelectedIndex(0); /*NONE*/
	rtAlpha.setEnabled(true);
	JLabel11.setEnabled(true);
	rtAlpha.setText("0.15");
	JLabel12.setEnabled(true);
	rtBeta.setEnabled(true);
	rtBeta.setText("0.2");
	rtM.setText("2"); 
	rtGamma.setText("NA");
	JLabel13.setEnabled(false);
	rtGamma.setEnabled(false);
	rtBWMin.setText("10");
	rtBWMax.setText("1024");
    }
  
    
    JLabel JLabel2 = new JLabel();
    JLabel JLabel3 = new JLabel();
    JLabel JLabel4 = new JLabel();
    JLabel JLabel5 = new JLabel();
    JLabel JLabel6 = new JLabel();
    JLabel JLabel7 = new JLabel();
    JLabel JLabel11 = new JLabel();
    JLabel JLabel12 = new JLabel();
    JLabel JLabel13 = new JLabel();
    JLabel JLabel14 = new JLabel();
    JTextField rtAlpha = new JTextField();
    JTextField rtBeta = new JTextField();
    JTextField rtGamma = new JTextField();
    JTextField rtM = new JTextField();
    JTextField rtHS = new JTextField();
    JTextField rtLS = new JTextField();
    JTextField rtN = new JTextField();
    
    String NP_RANDOM = "Random";
    String NP_HEAVYTAILED = "Heavy Tailed";
    String GT_ALL = "All";
    String GT_INCREMENTAL = "Incremental";
    String[] pcData = {"None", "On"};
    String[] clData = {"Off", "On" };
    String BW_CONSTANT = "Constant";
    String BW_UNIFORM = "Uniform";
    String BW_EXPONENTIAL = "Exponential";
    String BW_HEAVYTAILED = "Heavy Tailed";
    String RT_WAXMAN = "Waxman";
    String RT_BARABASI = "BA";
  String RT_BARABASI2 = "BA-2";
    String RT_GLP = "GLP";
    String RT_KRGN = "GN";  /*krapivsky-redner: not implemented yet*/
    
    String[] modelTypeData = {RT_WAXMAN, RT_BARABASI, RT_BARABASI2, RT_GLP};
    String[] bwData = {BW_CONSTANT, BW_UNIFORM, BW_EXPONENTIAL, BW_HEAVYTAILED};
    String[] gtData = {GT_ALL, GT_INCREMENTAL};        
    String[] npData = {NP_RANDOM, NP_HEAVYTAILED};
    
    JLabel BWLabel = new JLabel();
    JComboBox rtBWDist = new JComboBox(bwData);
    JLabel BWMaxLabel = new JLabel();
    JLabel BWMinLabel = new JLabel();
    JTextField rtBWMax = new JTextField();
    JTextField rtBWMin = new JTextField();

    
    
    JComboBox ModelType = new JComboBox(modelTypeData);
    JLabel RouterFileBeingReadLabel = new JLabel();
    JLabel JLabel36 = new JLabel();
    JLabel JLabel37 = new JLabel();
    JLabel JLabel38 = new JLabel();
    JLabel JLabel39 = new JLabel();
    JComboBox npComboBox= new JComboBox(npData);
    JComboBox pcComboBox = new JComboBox(pcData);
    JComboBox gtComboBox = new JComboBox(gtData);
    JComboBox clComboBox = new JComboBox(clData);
    JButton ImportRouterTopology = new JButton();
    JFileChooser fc;
    boolean isReadFromFile = false;
    String file = "";
    LineBorder lineBorder1 = new LineBorder(java.awt.Color.black);
    EtchedBorder etchedBorder1 = new EtchedBorder();
    EtchedBorder etchedBorder2 = new EtchedBorder();
 
    
}



