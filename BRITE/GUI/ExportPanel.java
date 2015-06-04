package GUI;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import java.io.*;           
import javax.swing.filechooser.*;

final class ExportPanel  extends JPanel  implements ActionListener {
    
    EtchedBorder etchedBorder1 = new EtchedBorder();
    LineBorder lineBorder1 = new LineBorder(java.awt.Color.black);
    JLabel JLabel30 = new JLabel();
    JLabel JLabel31 = new JLabel();
    
    JCheckBox otterFormat, briteFormat, dmlFormat,nsFormat, javasimFormat;
    JLabel JLabel32 = new JLabel();
    JTextField ExportLocation = new JTextField();
    JButton ExportLocationBrowse = new JButton();
    JFileChooser fc = new JFileChooser("");
    
    ExportPanel() { this.init(); } 
    
  public void actionPerformed(ActionEvent e)     { 
    if (e.getSource().equals(ExportLocationBrowse)) {
      try {
	fc.showSaveDialog(this);
	ExportLocation.setText(fc.getSelectedFile().getName());
      }
      catch (Exception eFC) {}
    }
  }
  /*its always brite format, whether its chcked or not because we need the brite format to convert to others*/
  public boolean isBriteFormat() {	return true; }  //return briteFormat.isSelected();    }
  public boolean isOtterFormat() {	return otterFormat.isSelected();    }
  public boolean isDMLFormat() {return dmlFormat.isSelected();    }
  public boolean isJavasimFormat() {	return javasimFormat.isSelected();    }
  public boolean isNSFormat() { return nsFormat.isSelected(); }

    void init() {
	this.setBorder(etchedBorder1);
	this.setLayout(null);
	this.setBounds(24,370,432,96);
	JLabel30.setText("Export Topology");
	this.add(JLabel30);
	JLabel30.setForeground(java.awt.Color.black);
	JLabel30.setBounds(12,12,156,16);
	JLabel31.setText("Formats:");
	this.add(JLabel31);
	JLabel31.setForeground(java.awt.Color.black);
	JLabel31.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel31.setBounds(24,60,95,20);
	
	briteFormat = new JCheckBox("BRITE");
	briteFormat.setSelected(true);
	this.add(briteFormat);
	briteFormat.setFont(new Font("SansSerif", Font.PLAIN, 12));
	briteFormat.setBounds(100, 60, 70, 24);
	//briteFormat.addActionListener(this);
	otterFormat = new JCheckBox("Otter");
	this.add(otterFormat);
	otterFormat.setToolTipText("Export for visualization in Otter");
	otterFormat.setFont(new Font("SansSerif", Font.PLAIN, 12));
	otterFormat.setBounds(170,60,70,24);
	//otterFormat.addActionListener(this);
	dmlFormat = new JCheckBox("SSF");
	this.add(dmlFormat);
	dmlFormat.setFont(new Font("SansSerif", Font.PLAIN, 12));
	dmlFormat.setBounds(240, 60, 70, 24);
	dmlFormat.setToolTipText("Export for simulation in SSFNet");
	//dmlFormat.addActionListener(this);
	nsFormat = new JCheckBox("NS");
	this.add(nsFormat);
	nsFormat.setFont(new Font("SansSerif", Font.PLAIN, 12));
	nsFormat.setBounds(310, 60, 50, 24);
	nsFormat.setToolTipText("Export for simulation in NS-2");
	
	javasimFormat = new JCheckBox("JSim");
	this.add(javasimFormat);
	javasimFormat.setFont(new Font("SansSerif", Font.PLAIN, 12));
	javasimFormat.setBounds(360, 60, 70, 24);
	javasimFormat.setToolTipText("Export for simulation in Javasim");

	JLabel32.setText("Location:");
	this.add(JLabel32);
	JLabel32.setForeground(java.awt.Color.black);
	JLabel32.setFont(new Font("SansSerif", Font.PLAIN, 12));
	JLabel32.setBounds(24,36,96,20);
	ExportLocation.setBorder(lineBorder1);
	ExportLocation.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.TEXT_CURSOR));
	this.add(ExportLocation);
	ExportLocation.setBounds(132,36,156,20);
	ExportLocationBrowse.setText("Browse...");
	ExportLocationBrowse.addActionListener(this);
	this.add(ExportLocationBrowse);
	ExportLocationBrowse.setFont(new Font("SansSerif", Font.PLAIN, 12));
	ExportLocationBrowse.setBounds(300,36,96,19);
	
    }
   
}

