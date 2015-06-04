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


final class BUPanel extends JPanel implements ActionListener {
    String BW_CONSTANT = "Constant";
    String BW_UNIFORM = "Uniform";
    String BW_EXPONENTIAL = "Exponential";
    String BW_HEAVYTAILED = "Heavy Tailed";
    String[] bwData = {BW_CONSTANT, BW_UNIFORM, BW_EXPONENTIAL, BW_HEAVYTAILED};
    JLabel BottomUpLabel = new JLabel();
    String BU_WALK = "Random Walk";
    String BU_PICK = "Random Pick";
    String[] BUData = {BU_WALK, BU_PICK};
    JLabel gLabel = new JLabel();
    JComboBox BottomUpComboBox = new JComboBox(BUData);
    JLabel ASAssignLabel = new JLabel();
    JLabel NumASNodesLabel = new JLabel();
    JTextField numAS = new JTextField();
    JComboBox ASAssignComboBox = new JComboBox(bwData); //prob dist are same as BW
    JLabel InterBWDistLabel = new JLabel();
    JLabel InterBWMinLabel = new JLabel();
    JLabel InterBWMaxLabel = new JLabel();
    JComboBox InterBWDist = new JComboBox(bwData);
    JTextField InterBWMax = new JTextField();
    JTextField InterBWMin = new JTextField();
    EtchedBorder etchedBorder1= new EtchedBorder();
    LineBorder lineBorder1 = new LineBorder(java.awt.Color.black);
    JButton selectRT = new JButton();
    GUI.Brite parent;

    void EnableComponents(boolean b) {
	int count = this.getComponentCount();
	for (int i=0; i<count; ++i) {
	    Component c = this.getComponent(i);
	    c.setEnabled(b);
	}
	if (!ASAssignComboBox.getSelectedItem().equals(BW_CONSTANT)) {
	    numAS.setEnabled(false);
	    NumASNodesLabel.setEnabled(false);
	}
    }
    
    void EnableBottomUp(boolean b) { 
	BottomUpComboBox.setEnabled(b);
	BottomUpLabel.setEnabled(b);
	
    }

    public BUPanel(GUI.Brite g) { 
      super(); 
      this.init(); 
      parent = g;
    }
    
    public void actionPerformed(ActionEvent e) {
	if (e.getSource().equals(ASAssignComboBox)) {
	    if (ASAssignComboBox.getSelectedItem().equals(BW_CONSTANT) ||
		ASAssignComboBox.getSelectedItem().equals(BW_EXPONENTIAL)) {
		numAS.setEnabled(true);
		NumASNodesLabel.setEnabled(true);
	    }
	    else {
		//numAS.setEnabled(false);
		//NumASNodesLabel.setEnabled(false);
	    }
	}
	else if (e.getSource().equals(selectRT)) {
	  parent.JTabbedPane1.setSelectedComponent(parent.rtPanel);
	}


    }

    void init() {
	this.setBorder(etchedBorder1);
	this.setLayout(null);
	this.setBackground(new java.awt.Color(204,204,204));
	this.setBounds(2,24,427,261);
	this.setVisible(false);
	
	BottomUpLabel.setText("Bottom-Up Topology Parameters");
	this.add(BottomUpLabel);
	BottomUpLabel.setForeground(java.awt.Color.black);
	BottomUpLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
	BottomUpLabel.setBounds(12,12,258 , 21);
	
	gLabel.setText("Grouping Model:");
	gLabel.setForeground(java.awt.Color.black);
	gLabel.setBounds(14, 48, 170, 21);
	gLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	this.add(gLabel);
	this.add(BottomUpComboBox);
	BottomUpComboBox.setBounds(180, 48, 165, 21);
	BottomUpComboBox.setFont(new Font("SansSerif", Font.PLAIN, 12));

	ASAssignLabel.setText("AS Assignment:");
	ASAssignLabel.setForeground(java.awt.Color.black);
	ASAssignLabel.setBounds(14, 72, 120, 21);
	ASAssignLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	this.add(ASAssignLabel);
	
	ASAssignComboBox.setBounds(130, 72, 115, 21);
	ASAssignComboBox.setFont(new Font("SansSerif", Font.PLAIN, 12));
	ASAssignComboBox.addActionListener(this);
	this.add(ASAssignComboBox);
	
	NumASNodesLabel.setText("Number of AS:");
	NumASNodesLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	NumASNodesLabel.setForeground(java.awt.Color.black);
	NumASNodesLabel.setBounds(250, 72, 100, 21);
	this.add(NumASNodesLabel);
	NumASNodesLabel.setEnabled(false);

	numAS.setBorder(lineBorder1);
	numAS.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(numAS);
	numAS.setEnabled(false);
	numAS.setBounds(351,72 ,46, 18);
	numAS.setText("100");
	
	//////BottomUp BW stuff
	/*inter bw - ie connecting ASes*/
	InterBWDistLabel.setText("Inter BW Dist:");
	InterBWDistLabel.setForeground(java.awt.Color.black);
	InterBWDistLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	InterBWDistLabel.setBounds(14, 95, 120, 21);
	this.add(InterBWDistLabel);
	InterBWDist.setBounds(130, 95, 115, 21);
	InterBWDist.setFont(new Font("SansSerif",Font.PLAIN, 12));
	InterBWDist.addActionListener(this);
	this.add(InterBWDist);

	InterBWMaxLabel.setText("Max BW:");
	this.add(InterBWMaxLabel);
	InterBWMaxLabel.setForeground(java.awt.Color.black);
	InterBWMaxLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	InterBWMaxLabel.setBounds(20,118, 55, 21);
	InterBWMinLabel.setText("Min BW:");
	this.add(InterBWMinLabel);
	InterBWMinLabel.setForeground(java.awt.Color.black);
	InterBWMinLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
	InterBWMinLabel.setBounds(20,140,  55, 21);
	InterBWMax.setBorder(lineBorder1);
	InterBWMax.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(InterBWMax);
	InterBWMax.setBounds(77,118,46,18);
	InterBWMin.setBorder(lineBorder1);
	InterBWMin.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(InterBWMin);
	InterBWMin.setBounds(77,140,46,18);
	InterBWMin.setText("10");
	InterBWMax.setText("1024");
	
	
	selectRT.setText("Set Router Parameters");
	selectRT.setFont(new Font("SansSerif", Font.PLAIN, 12));
	selectRT.addActionListener(this);
	selectRT.setBounds(14, 165, 150, 21);
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
	
	String groupMethStr = (String) BottomUpComboBox.getSelectedItem();
	int groupM = 1; //i.e. RANDOM_PICK
	if (groupMethStr.equals(BU_WALK))
	    groupM = 2;
	
	String assignStr = (String)ASAssignComboBox.getSelectedItem();
	int assignT = 1; //i.e. CONSTANT
	if (assignStr.equals(BW_UNIFORM))
	    assignT = 2;
	else if (assignStr.equals(BW_HEAVYTAILED))
	    assignT = 3;
	else if (assignStr.equals(BW_EXPONENTIAL))
	    assignT = 4;
	int numOfAS = (int) getNumFromTextField(numAS, -1); //default to 100?
	
	//inter BW parse:
	String interBWStr = (String) InterBWDist.getSelectedItem();
	int interBW=1; //init it to  constant 
	if (interBWStr.equals(BW_UNIFORM))
	    interBW = 2;
	else if (interBWStr.equals(BW_HEAVYTAILED))
	    interBW = 3;
	else if (interBWStr.equals(BW_EXPONENTIAL))
	    interBW = 4;
	double interBWMax = getNumFromTextField(InterBWMax,1024);
	double interBWMin = getNumFromTextField(InterBWMin,1);
	
	try {
	    bw.write("BeginModel");
	    bw.newLine();
	    bw.write("\tName = 6\t\t #Bottom Up  = 6");
	    bw.newLine();
	    bw.write("\tGrouping = "+ groupM+"\t\t #Random Pick = 1, Random Walk = 2");
	    bw.newLine();
	    bw.write("\tAssignType = " + assignT + "\t\t #Constant = 1, Uniform =2, HeavyTailed = 3, Exponential =4");      
	    bw.newLine();
	    bw.write("\tNumAS = "+numOfAS+"\t\t #Only needed if AssignType is constant or exponential.  Otherwise use -1");
	    bw.newLine();
	    bw.write("\tBWInter = "+ interBW + "\t\t #Constant = 1, Uniform =2, HeavyTailed = 3, Exponential =4");      
	    bw.newLine();
	    bw.write("\tBWInterMin = " + interBWMin); bw.newLine();
	    bw.write("\tBWInterMax = " + interBWMax); bw.newLine();
	    bw.write("EndModel");
	    bw.newLine();
	}
	catch (IOException e) {
	    System.out.println("[BRITE ERROR]: Could not create config file. " + e);
	    System.exit(0);
	}
	
	
    }
    










    
}




