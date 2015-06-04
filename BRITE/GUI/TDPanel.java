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


public final class TDPanel extends JPanel implements ActionListener {
    JLabel JLabel1 = new JLabel();
    EtchedBorder etchedBorder1= new EtchedBorder();
    LineBorder lineBorder1 = new LineBorder(java.awt.Color.black);
    JLabel TDLabel = new JLabel();
    String TD_RANDOM = "Random";
    String TD_SMALLEST_DEG = "Smallest-Degree";
    String TD_SMALLEST_DEG_NOLEAF = "Smallest-Degree NonLeaf";
    String TD_SMALLEST_K_DEG = "Smallest k-Degree";
    String[] TDdata = {TD_RANDOM, TD_SMALLEST_DEG, TD_SMALLEST_DEG_NOLEAF, TD_SMALLEST_K_DEG};
    String BW_CONSTANT = "Constant";
    String BW_UNIFORM = "Uniform";
    String BW_EXPONENTIAL = "Exponential";
    String BW_HEAVYTAILED = "Heavy Tailed";
    String[] bwData = {BW_CONSTANT, BW_UNIFORM, BW_EXPONENTIAL, BW_HEAVYTAILED};

    JLabel kLabel = new JLabel();
    JTextField kText = new JTextField();
     
    JComboBox TDComboBox = new JComboBox(TDdata);
    
    JLabel InterBWDistLabel = new JLabel();
    JLabel InterBWMinLabel = new JLabel();
    JLabel InterBWMaxLabel = new JLabel();
    JComboBox InterBWDist = new JComboBox(bwData);
    JTextField InterBWMax = new JTextField();
    JTextField InterBWMin = new JTextField();

    JLabel IntraBWDistLabel = new JLabel();
    JLabel IntraBWMaxLabel = new JLabel();
    JLabel IntraBWMinLabel = new JLabel();
    
    JButton selectRT = new JButton();
    JButton selectAS = new JButton();

    
    JComboBox IntraBWDist = new JComboBox(bwData);
    JTextField IntraBWMax = new JTextField();
    JTextField IntraBWMin = new JTextField();
    GUI.Brite parent;
    
    void EnableTopDown(boolean b) { 
	TDComboBox.setEnabled(b);
	TDLabel.setEnabled(b);
    }


    void EnableComponents(boolean b) {
	for (int i=0; i<this.getComponentCount(); ++i) {
	    Component c = this.getComponent(i);
	    c.setEnabled(b);
	}
	if (!TDComboBox.getSelectedItem().equals(TD_SMALLEST_K_DEG)) {
	    kText.setEnabled(false);
	    kLabel.setEnabled(false);
	}
    }
    
    
    public TDPanel(GUI.Brite gd) { 
	super(); 
	this.init(); 
	parent = gd;
    }
    
    public void actionPerformed(ActionEvent e) {
	if (e.getSource().equals(TDComboBox)){
	    if (TDComboBox.getSelectedItem().equals(TD_SMALLEST_K_DEG)) {
		kText.setEnabled(true);
		kLabel.setEnabled(true);
	    }
	    else {
		kText.setEnabled(false);
		kLabel.setEnabled(false);
	    }
	}
	else if (e.getSource().equals(selectRT)) {
	    parent.JTabbedPane1.setSelectedComponent(parent.rtPanel);
	}
	else if (e.getSource().equals(selectAS)) {
	    parent.JTabbedPane1.setSelectedComponent(parent.asPanel);
	}
    }
    
    void init() {
	this.setBorder(etchedBorder1);
	this.setLayout(null);
	this.setBackground(new java.awt.Color(204,204,204));
	this.setBounds(2,24,427,261);
	this.setVisible(false);
	JLabel1.setText("Top Down Topology Parameters");
	this.add(JLabel1);
	JLabel1.setForeground(java.awt.Color.black);
	JLabel1.setBounds(12,12,258,16);
	JLabel1.setFont(new Font("SansSerif", Font.BOLD, 12));
	

	TDLabel.setText("Edge Connection Model: ");
	this.add(TDLabel);
	TDLabel.setForeground(java.awt.Color.black);
	TDLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	TDLabel.setBounds(14,48,170, 21);
	this.add(TDComboBox);
	TDComboBox.setBounds(180, 48, 165, 21);
	TDComboBox.setFont(new Font("SansSerif", Font.PLAIN, 12));
	TDComboBox.addActionListener(this);
	kLabel.setText("k: ");
	this.add(kLabel);
	kLabel.setForeground(java.awt.Color.black);
	kLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	kLabel.setBounds(350, 48, 21,21);
	kLabel.setEnabled(false);
	
	kText.setBorder(lineBorder1);
	kText.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(kText);
	kText.setBounds(370, 48, 46, 18);
	kText.setEnabled(false);
	

	//////TopDown BW stuff
	/*inter bw - ie connecting ASes*/
	InterBWDistLabel.setText("Inter BW Dist:");
	InterBWDistLabel.setForeground(java.awt.Color.black);
	InterBWDistLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	InterBWDistLabel.setBounds(14, 75, 90, 21);
	this.add(InterBWDistLabel);
	InterBWDist.setBounds(107, 75, 90, 21);
	InterBWDist.setFont(new Font("SansSerif",Font.PLAIN, 12));
	InterBWDist.addActionListener(this);
	this.add(InterBWDist);
	
	InterBWMaxLabel.setText("Max BW:");
	this.add(InterBWMaxLabel);
	InterBWMaxLabel.setForeground(java.awt.Color.black);
	InterBWMaxLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	InterBWMaxLabel.setBounds(20,100, 55, 21);
	InterBWMinLabel.setText("Min BW:");
	this.add(InterBWMinLabel);
	InterBWMinLabel.setForeground(java.awt.Color.black);
	InterBWMinLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	InterBWMinLabel.setBounds(20,125,  55, 21);
	InterBWMax.setBorder(lineBorder1);
	InterBWMax.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(InterBWMax);
	InterBWMax.setBounds(77,100,46,18);
	InterBWMin.setBorder(lineBorder1);
	InterBWMin.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(InterBWMin);
	InterBWMin.setBounds(77,125,46,18);
	InterBWMin.setText("10");
	InterBWMax.setText("1024");
	
	selectAS.setText("Set AS Parameters");
	selectAS.setFont(new Font("SansSerif", Font.PLAIN, 12));
	selectAS.addActionListener(this);
	selectAS.setBounds(14, 150, 130, 21);
	selectAS.setForeground(java.awt.Color.black);
	selectAS.setBorder(lineBorder1);
	this.add(selectAS);
	
	/*intra bw - ie connecting routers*/
	IntraBWDistLabel.setText("Intra BW Dist:");
	IntraBWDistLabel.setForeground(java.awt.Color.black);
	IntraBWDistLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	IntraBWDistLabel.setBounds(225 ,75, 90, 21);
	this.add(IntraBWDistLabel);	
	IntraBWDist.setBounds(316, 75, 90, 21);
	IntraBWDist.setFont(new Font("SansSerif", Font.PLAIN, 12));
	IntraBWDist.addActionListener(this);
	this.add(IntraBWDist);

	
	IntraBWMaxLabel.setText("Max BW:");
	this.add(IntraBWMaxLabel);
	IntraBWMaxLabel.setForeground(java.awt.Color.black);
	IntraBWMaxLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	IntraBWMaxLabel.setBounds(231,100, 55, 21);
	IntraBWMinLabel.setText("Min BW:");
	this.add(IntraBWMinLabel);
	IntraBWMinLabel.setForeground(java.awt.Color.black);
	IntraBWMinLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	IntraBWMinLabel.setBounds(231,125, 55, 21);
	IntraBWMax.setBorder(lineBorder1);
	IntraBWMax.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(IntraBWMax);
	IntraBWMax.setBounds(290,100,46,18);
	IntraBWMin.setBorder(lineBorder1);
	IntraBWMin.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(IntraBWMin);
	IntraBWMin.setBounds(290,125,46,18);
	IntraBWMin.setText("10");
	IntraBWMax.setText("1024");
	
	
	selectRT.setText("Set Router Parameters");
	selectRT.setFont(new Font("SansSerif", Font.PLAIN, 12));
	selectRT.addActionListener(this);
	selectRT.setBounds(231, 150, 150, 21);
	selectRT.setBorder(lineBorder1);
	selectRT.setForeground(java.awt.Color.black);
	this.add(selectRT);
	
	
	
    }

    /************* Generate Config File Routines  ************************/
    
    private double getNumFromTextField(JTextField c, double defVal) {
	if (!c.isEnabled())
	    return -1;
	String nstr = c.getText();
	Double n=new Double(defVal);
	try {
	    n = new Double(nstr);
	} 
	catch (Exception e) { 
	    System.out.println("Exception:  textfield str = " + nstr);
	}
	return n.doubleValue();
    }
    
  
  
    public void WriteConf(BufferedWriter bw) {
	String edgeConnStr = (String) TDComboBox.getSelectedItem();
	int edgeConn=1;  //init to Random
	if (edgeConnStr.equals(TD_SMALLEST_DEG))
	    edgeConn = 2;
	else if (edgeConnStr.equals(TD_SMALLEST_DEG_NOLEAF))
	    edgeConn = 3;
	else if (edgeConnStr.equals(TD_SMALLEST_K_DEG))
	    edgeConn = 4;
	int k = (int) getNumFromTextField(kText,-1);
        
	//inter BW parse:
	String interBWStr = (String) InterBWDist.getSelectedItem();
	int interBW=1;  //init to constant
	 if (interBWStr.equals(BW_UNIFORM))
	    interBW = 2;
	else if (interBWStr.equals(BW_HEAVYTAILED))
	    interBW = 3;
	else if (interBWStr.equals(BW_EXPONENTIAL))
	    interBW = 4;
	double interBWMax = getNumFromTextField(InterBWMax,1024);
	double interBWMin = getNumFromTextField(InterBWMin,1);
	
	//intra BW parse:
	String intraBWStr =(String)  IntraBWDist.getSelectedItem();
	int intraBW=1; //init to constant
	 if (intraBWStr.equals(BW_UNIFORM))
	    intraBW = 2;
	else if (intraBWStr.equals(BW_HEAVYTAILED))
	    intraBW = 3;
	else if (intraBWStr.equals(BW_EXPONENTIAL))
	    intraBW = 4;
	double intraBWMax = getNumFromTextField(IntraBWMax, 1024);
	double intraBWMin = getNumFromTextField(IntraBWMin, 1);
	/*  Sample Top Down Config File must include all the following fields
	     BeginModel
	            Name = 5
	            edgeConn = 1
	            k = 1
	            //HS = 1000
	            //LS = 100
	            BWInter = 2
	            BWInterMin = 155
	            BWInterMax = 1024
	            BWIntra = 2
	            BWIntraMin = 10
	            BWIntraMax = 155
	      EndModel
	*/
	
	try {
	    bw.write("BeginModel");
	    bw.newLine();
	    bw.write("\tName = 5\t\t #Top Down = 5");
	    bw.newLine();
	    bw.write("\tedgeConn = "+edgeConn +"\t\t #Random=1, Smallest Nonleaf = 2, Smallest Deg = 3, k-Degree=4");
	    bw.newLine();
	    bw.write("\tk = "+k+"\t\t\t #Only needed if edgeConn is set to K-Degree, otherwise use -1");
	    bw.newLine();
	    bw.write("\tBWInter = "+ interBW + "\t\t #Constant = 1, Uniform =2, HeavyTailed = 3, Exponential =4");      
	    bw.newLine();
	    bw.write("\tBWInterMin = " + interBWMin); bw.newLine();
	    bw.write("\tBWInterMax = " + interBWMax); bw.newLine();
	    bw.write("\tBWIntra = " + intraBW +"\t\t #Constant = 1, Uniform =2, HeavyTailed = 3, Exponential =4");      
	    bw.newLine();
	    bw.write("\tBWIntraMin = " + intraBWMin); bw.newLine();
	    bw.write("\tBWIntraMax = " + intraBWMax); bw.newLine();
	    bw.write("EndModel");
	    
	    bw.newLine();
	    bw.newLine();

	    //write AS conf
	    parent.asPanel.WriteConf(bw, interBW, interBWMin, interBWMax);
	    
	    bw.newLine();
	    bw.newLine();
	    //write router conf
	    parent.rtPanel.WriteConf(bw, intraBW, intraBWMin, intraBWMax);
	}
	catch (IOException e) {
	    System.out.println("[BRITE ERROR]: Could not create config file. " + e);
	    System.exit(0);
	}

       
	
	
    }
    
    


}
















