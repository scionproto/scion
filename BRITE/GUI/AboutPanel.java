package GUI;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;


final class AboutPanel extends JDialog implements ActionListener {
    JEditorPane editPane;
    LineBorder lineBorder1 = new LineBorder(java.awt.Color.black);
    JButton closeB = new JButton();
    JScrollPane scrollPane1;

    public void actionPerformed(ActionEvent e) {
	if (e.getSource().equals(closeB)) {
	    setVisible(false);
	}
    }
    
    public void processWindowEvent(WindowEvent e) {
	super.processWindowEvent(e);
	if (e.getSource() == this && e.getID() == e.WINDOW_CLOSING) {
	  setVisible(false);
	}
    }
      
    public AboutPanel() {
	super();
	super.dialogInit();
	setSize(300,300);
	setResizable(false);
	
	
	getContentPane().setLayout(null);
	getContentPane().setBackground(new java.awt.Color(204,204,204));
	
	getContentPane().add(closeB);
	closeB.setBounds(80, 260, 100, 21);
	closeB.setText("Close Window");
	closeB.setFont(new Font("SansSerif", Font.PLAIN, 10));
	closeB.setBorder(lineBorder1);
	closeB.addActionListener(this);
	closeB.setVisible(true);
	       
	editPane = new JEditorPane();
	String s= null;
	try {
	    String slash = System.getProperty("file.separator");
	    s = "file:GUI"+slash+"help"+slash+"about.html";
	    editPane.setPage(new java.net.URL(s));
	}
	catch (Exception e) {
	  System.out.println("[BRITE ERROR] Could not read about file " + e);
	}
	editPane.setEditable(false);
	editPane.setBounds(10,10,280,240);
	scrollPane1 = new JScrollPane(editPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	getContentPane().add(scrollPane1);
	scrollPane1.setBounds(10, 10, 280, 240);
	
	setTitle("About BRITE");
	setSize(getPreferredSize());
    }



}




