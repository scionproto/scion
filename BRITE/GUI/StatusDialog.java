package GUI;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;




final class StatusDialog extends JDialog implements ActionListener {
    JButton closeB = new JButton("Close Status Window");
    JButton cancelB = new JButton("Cancel Generation");
    JTextArea statusText = new JTextArea();
    JScrollPane scrollPane1;
    LineBorder lineBorder1 = new LineBorder(java.awt.Color.black);
    GUI.Brite parent =null;
    
    
    public void actionPerformed(ActionEvent e) {
	if (e.getSource().equals(closeB)) {
	    statusText.setText("");
	    setVisible(false);
	}
	if (e.getSource().equals(cancelB)) {
	  parent.p.destroy();
	  statusText.append("*** Generation Cancelled by user. ***");

	}
    }

    public void processWindowEvent(WindowEvent e) {
	super.processWindowEvent(e);
	if (e.getSource() == this && e.getID() == e.WINDOW_CLOSING) {
	    statusText.setText("");
	    setVisible(false);
	}
    }

       
    public JTextArea getTextArea() { return statusText; }
    public JScrollPane getScroll() { return scrollPane1; }
    public JButton getButton() { return closeB; }
    public StatusDialog(GUI.Brite parent) {
	super();
	super.dialogInit();
	//	setSize(400,400);
	setResizable(true);
	
	this.parent = parent; //we need this because sometimes we need to kill the process while its executing
	
	getContentPane().setLayout(null);
	getContentPane().setBackground(new java.awt.Color(204,204,204));
	
	getContentPane().add(closeB);
	closeB.setBounds(200, 170, 100, 21);
	closeB.setText("Close Window");
	closeB.setFont(new Font("SansSerif", Font.PLAIN, 10));
	closeB.setBorder(lineBorder1);
	closeB.addActionListener(this);
	closeB.setVisible(true);
	
	getContentPane().add(cancelB);
	cancelB.setBounds(75,170, 100, 21);
	cancelB.setText("Cancel Generation");
	cancelB.setFont(new Font("SansSerif", Font.PLAIN, 10));
	cancelB.addActionListener(this);
	cancelB.setBorder(lineBorder1);
	cancelB.setVisible(true);
       
	
	statusText.setFont(new Font("SansSerif", Font.PLAIN, 10));
	statusText.setBounds(10,10,380,150);
	statusText.setLineWrap(true);
	statusText.setEditable(false);
	
	scrollPane1 = new JScrollPane(statusText, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	getContentPane().add(scrollPane1);
	scrollPane1.setBounds(10, 10, 380, 150);
	//	scrollPane1.getViewport().setScrollMode(JViewport.BLIT_SCROLL_MODE);
	
	setTitle("Status Window");
	setSize(getPreferredSize());
    }

  
  

}




