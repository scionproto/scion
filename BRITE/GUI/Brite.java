package GUI;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import java.lang.Runtime;   //so that we can call BriteC++ or BriteJava executable in native format
import java.io.*;           //to redirect stdout for runtime process (c++ or java)

import Import.*;

public final class Brite extends JDialog implements ActionListener, Runnable
{
    
    public void init()
    {
	getContentPane().setLayout(null);
	getContentPane().setBackground(new java.awt.Color(204,204,204));
	setSize(494,550);
	JLabel1.setText("Topology Type:");
	getContentPane().add(JLabel1);
	JLabel1.setForeground(java.awt.Color.black);
	JLabel1.setFont(new Font("SansSerif", Font.BOLD,   12));
	JLabel1.setBounds(36,12,156,22);
	getContentPane().add(TopologyType);
	TopologyType.setFont(new Font("SansSerif", Font.PLAIN, 12));
	TopologyType.setBounds(170,12,202,26);
	TopologyType.addActionListener(this);
	getContentPane().add(ePanel);
	
	//begin launch briana buttons --- 
	// XXX briana not included in this version, so overwriting it as Exit button
	LaunchBriana.setText("Exit ");
	LaunchBriana.setActionCommand("Exit");
	LaunchBriana.setBorder(lineBorder1);
	getContentPane().add(LaunchBriana);
	LaunchBriana.setForeground(java.awt.Color.black);
	LaunchBriana.setFont(new Font("SansSerif", Font.PLAIN, 12));
	LaunchBriana.setBounds(24,474,50,21);
	//	LaunchBriana.setBounds(100,474,108,21);
	LaunchBriana.addActionListener(this);
	
	HelpButton.setText("Help");
	HelpButton.setBorder(lineBorder1);
	getContentPane().add(HelpButton);
	HelpButton.setForeground(java.awt.Color.black);
	HelpButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
	//HelpButton.setBounds(24, 474, 50,21);
	HelpButton.setBounds(100,474,50,21);
	HelpButton.addActionListener(this);
	
	
	/*BEGIN: run C++ or Java exe choice*/
	getContentPane().add(ExeChoicesComboBox);
	ExeChoicesComboBox.setFont(new Font("SansSerif", Font.PLAIN,   12));
	ExeChoicesComboBox.setBounds(220,474,110,21);
	/*END: C++ or Java exe choice*/
	
	
	
	
	/*BEGIN: Build Topology Button*/
	BuildTopology.setText("Build Topology");
	BuildTopology.setActionCommand("Build Topology");
	BuildTopology.setBorder(lineBorder1);
	getContentPane().add(BuildTopology);
	BuildTopology.setForeground(java.awt.Color.black);
	BuildTopology.setFont(new Font("SansSerif", Font.PLAIN, 12));
	BuildTopology.setBounds(348,474,108,21);
	BuildTopology.addActionListener(this);
	/*END: Build Topology Button*/
	
	getContentPane().add(logo);
	logo.setBorder(null);
	logo.setBounds(389, 2, 67, 65);
	logo.addActionListener(this);

	getContentPane().add(JTabbedPane1);
	JTabbedPane1.setBackground(new java.awt.Color(153,153,153));
	JTabbedPane1.setBounds(24,48,432,315);
	JTabbedPane1.add(asPanel);
	JTabbedPane1.add(rtPanel);
	JTabbedPane1.add(tdPanel);
	JTabbedPane1.add(buPanel);
	JTabbedPane1.setTitleAt(0,"AS");
	JTabbedPane1.setTitleAt(1,"Router");
	JTabbedPane1.setTitleAt(2,"Top Down");
	JTabbedPane1.setTitleAt(3, "Bottom Up");
	JTabbedPane1.setSelectedIndex(0);
	JTabbedPane1.setSelectedComponent(asPanel);
	rtPanel.EnableComponents(false);
	rtDisabled=true;
	hDisabled=true;
	tdPanel.EnableComponents(false);
	buPanel.EnableComponents(false);
      
	
	//create status window where output of executable will be written
	sd.setSize(400,200);
	//sd.setSize(sd.getPreferredSize());
	sd.setVisible(false);
	
	aboutPanel.setSize(300,300);
	aboutPanel.setVisible(false);

	
	hPanel.setSize(500,500);
	hPanel.setVisible(false);
	setTitle("Boston University Representative Internet Topology Generator (BRITE)");
    }

    

    public void actionPerformed(ActionEvent e) { 
      if (e.getSource().equals(HelpButton)) {
	hPanel.setVisible(true);
	return;
      }
      if (e.getSource().equals(logo)) {
	  aboutPanel.setVisible(true);
	  return;
      }
      String level = (String)TopologyType.getSelectedItem();
	if (e.getSource().equals(TopologyType)) {
	    level = (String)TopologyType.getSelectedItem();
	    if (level.equals(AS_TOPOLOGY)){
		JTabbedPane1.setSelectedComponent(asPanel);
		rtPanel.EnableComponents(false);
		tdPanel.EnableComponents(false);
		buPanel.EnableComponents(false);
		asPanel.EnableComponents(true);
		
	    }
	    else if (level.equals(ROUTER_TOPOLOGY)){
		JTabbedPane1.setSelectedComponent(rtPanel);
		tdPanel.EnableComponents(false);
		buPanel.EnableComponents(false);
		asPanel.EnableComponents(false);
		rtPanel.EnableComponents(true);
		
	    }
	    else if (level.equals(TOPDOWN_TOPOLOGY)) {
		JTabbedPane1.setSelectedComponent(tdPanel);
		tdPanel.EnableComponents(true);
		buPanel.EnableComponents(false);
		asPanel.EnableComponents(true);
		asPanel.EnableBW(false);
		rtPanel.EnableComponents(true);
		rtPanel.EnableBW(false);
	    }
	    else if (level.equals(BOTTOMUP_TOPOLOGY)) {
		JTabbedPane1.setSelectedComponent(buPanel);
		buPanel.EnableComponents(true);
		asPanel.EnableComponents(false);
		tdPanel.EnableComponents(false);
		rtPanel.EnableComponents(true);
	
	    }
	}

	else if (e.getSource().equals(BuildTopology)) {
	    String file = ((String)ePanel.ExportLocation.getText()).trim();
	    
	    if (file.equals("") || file==null){
		JOptionPane.showMessageDialog(this, "Error:  Missing Export File", "Error", JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    
	    if (!ePanel.isBriteFormat() && !ePanel.isOtterFormat() && !ePanel.isDMLFormat() && !ePanel.isNSFormat()) {
		JOptionPane.showMessageDialog(this, "Error: Must specify atleast one output format", "Error", JOptionPane.ERROR_MESSAGE);
		return;
	    }
	     sd.getTextArea().setText("");
	     if (!sd.isVisible())
	       sd.setVisible(true);
	     sd.repaint();
	     
	    String args = " GUI_GEN.conf  "+file;
	    BuildTopology.setEnabled(false);
	   
	    MakeConfFile(level);
	    
	    
	    runThread = new Thread(GUI.Brite.this);
	    runThread.setPriority(Thread.MAX_PRIORITY);
	    runThread.start();
	    
	    BuildTopology.setEnabled(true);
	    
	    //  runExecutable(args);
	    
	}

	else if (e.getSource().equals(LaunchBriana)) {
	    try {
	      System.exit(0);

	      /*String initFile = ".briana";
		GUI.Briana g = new GUI.Briana(initFile);
	      */
	    }
	    catch (Exception eBriana) {
	      //JOptionPane.showMessageDialog(this, "Could not start Briana. \n"+eBriana, "Error", JOptionPane.ERROR_MESSAGE);
	    }
	}
    }
   
  //this is for C++ version 
  public void ConvertBriteToExportFormat(String file) throws Exception {
    Rectangle rect = sdLog.getVisibleRect();
    int a = sdLog.getScrollableBlockIncrement(rect, SwingConstants.VERTICAL, 1);
    rect.setLocation((int)rect.getX(), (int)rect.getY()+a);
    sdLog.scrollRectToVisible(rect);

    File f = new File(file);
    if (!f.exists()) {
	sdLog.append(" Cannot find file " + file+" to convert to export format..");
      return;
    }
      
    
    int format=Model.ModelConstants.RT_FILE;
    String topologyType = (String)TopologyType.getSelectedItem();
    if (topologyType.equals(AS_TOPOLOGY))
      format = Model.ModelConstants.AS_FILE;
      
    if (ePanel.isOtterFormat()) {
	sdLog.append("Converting to Otter format ...\n");
	sdLog.paintImmediately(sdLog.getVisibleRect());
	Export.OtterExport.convert(file, format);
	sdLog.append("... DONE\n");
	sdLog.paintImmediately(sdLog.getVisibleRect());
    }
    
    if (ePanel.isDMLFormat()) {
      sdLog.append("Converting to SSF/DML format ..\n");
      sdLog.paintImmediately(sdLog.getVisibleRect());
      Export.DMLExport.convert(file, format);
      sdLog.append("... DONE\n");
      sdLog.paintImmediately(sdLog.getVisibleRect());
    }
    
    if (ePanel.isNSFormat()) {
      sdLog.append("Converting to NS format ..\n");
      sdLog.paintImmediately(sdLog.getVisibleRect());
      Export.NSExport.convert(file, format);
      sdLog.append("... DONE\n");
      sdLog.paintImmediately(sdLog.getVisibleRect());
    }
    
    if (ePanel.isJavasimFormat()) {
      sdLog.append("Converting to Javasim format ..\n");
      sdLog.paintImmediately(sdLog.getVisibleRect());
      Export.JSimExport.convert(file, format);
      sdLog.append("... DONE\n");
      sdLog.paintImmediately(sdLog.getVisibleRect());
    }
    a = sdLog.getScrollableBlockIncrement(rect, SwingConstants.VERTICAL, 1);
    rect.setLocation((int)rect.getX(), (int)rect.getY()+a);
    sdLog.scrollRectToVisible(rect);
    sdLog.paintImmediately(sdLog.getVisibleRect());
    
  }

  public void run() {
    String file = ((String)ePanel.ExportLocation.getText()).trim();
    String args = " GUI_GEN.conf " + file;
    
    /*make sure all import files are first converted to brite format*/
    if (asPanel.needConvert) {
      asPanel.ConvertFileToBriteFormat();
    }
    if (rtPanel.needConvert) {
      rtPanel.ConvertFileToBriteFormat();
    }
    
    runExecutable(args);
    
    if ( ((String)ExeChoicesComboBox.getSelectedItem()).equals(CPPEXE)) {
      if (ePanel.isOtterFormat() || ePanel.isNSFormat() || ePanel.isJavasimFormat() || ePanel.isDMLFormat())
	try {
	  ConvertBriteToExportFormat(file+".brite");
	}
	catch(Exception convertE) {
	  sdLog.append(" Error in converting brite format file to export formats. " + convertE);
	  
	}
    }  
    
    BuildTopology.setEnabled(true);
  }
  
  private void MakeConfFile(String topologyType) {
    try {
      BufferedWriter bw = new BufferedWriter(new FileWriter(new File("GUI_GEN.conf")));
      bw.write("#This config file was generated by the BRITE GUI. ");
      bw.newLine();  bw.newLine();
      bw.write("BriteConfig");
      bw.newLine(); bw.newLine();
      if (topologyType.equals(TOPDOWN_TOPOLOGY)) {
	tdPanel.WriteConf(bw);
	/*  
	    tdPanel handles this stuff now b/c we need to set bandwidth from td params:: 
	    bw.newLine();
	    asPanel.WriteConf(bw);
	    bw.newLine();
	    rtPanel.WriteConf(bw);
	*/
      }
      else if (topologyType.equals(BOTTOMUP_TOPOLOGY)) {
	buPanel.WriteConf(bw);
	bw.newLine();
	rtPanel.WriteConf(bw);
	bw.newLine();
      }
      else if (topologyType.equals(AS_TOPOLOGY))
	asPanel.WriteConf(bw);
      else if (topologyType.equals(ROUTER_TOPOLOGY))
	rtPanel.WriteConf(bw);
      
      bw.newLine();
      bw.write("BeginOutput");
      bw.newLine();
      bw.write("\tBRITE = ");
      if (ePanel.isBriteFormat()) 	
	bw.write("1 ");
      else 
	bw.write("0 " );
      bw.write("\t #1/0=enable/disable output in BRITE format");
      bw.newLine();
      bw.write("\tOTTER = ");
      if (ePanel.isOtterFormat())
	bw.write("1 " );
      else bw.write("0 ");
      bw.write("\t #1/0=enable/disable visualization in otter");
      bw.newLine();
      bw.write("\tDML = ");
      if (ePanel.isDMLFormat())
	bw.write("1 ");
      else bw.write("0 ");
      bw.write("\t #1/0=enable/disable output to SSFNet's DML format ");
      bw.newLine();
      bw.write("\tNS = ");
      if (ePanel.isNSFormat())
	bw.write("1 ");
      else bw.write("0");
      bw.write("\t #1/0=enable/disable output to NS-2");
      bw.newLine();
      bw.write("\tJavasim = ");
      if (ePanel.isJavasimFormat())
	bw.write("1 ");
      else bw.write("0");
      bw.write("\t #1/0=enable/disable output to Javasim");
      bw.newLine();
      
      bw.write("EndOutput");
      bw.newLine();
      bw.close();
    }
    catch (IOException e) { 
      System.out.println("[BRITE ERROR]:  Cannot create config file. " );
      e.printStackTrace();
      return;
    }
  }
    
  
  private void runExecutable(String args) {
    String outFile = ((String)ePanel.ExportLocation.getText()).trim();
    String sep = System.getProperty("file.separator");
    
    String cmdExe ="java -Xmx256M -classpath Java/:../:. Main.Brite ";
    boolean runC = false;
    
    if ( ((String)ExeChoicesComboBox.getSelectedItem()).equals(CPPEXE)) {
      runC= true;
      cmdExe = "bin"+sep+"cppgen ";
    }
    System.out.println(cmdExe);
    
    String runThis = cmdExe+ args;
    Runtime r= Runtime.getRuntime();
    try {

	runThis +=" seed_file"; /*Both generation engines require a seed file*/

      
      System.out.println("[MESSAGE]: GUI starting executable: "+runThis); 
	  p = r.exec(runThis);
	  InputStream in = p.getInputStream();
	  BufferedReader brIn = new BufferedReader(new InputStreamReader(in));
	  String line;
	  
	  sdLog = sd.getTextArea();
	  
	  while ((line= brIn.readLine())!=null) {
	    sdLog.append(line+"\n");
	    Rectangle rect = sdLog.getVisibleRect();
	    int a = sdLog.getScrollableBlockIncrement(rect, SwingConstants.VERTICAL, 1);
	    rect.setLocation((int)rect.getX(), (int)rect.getY()+a);
	    sdLog.scrollRectToVisible(rect);
	    System.out.println(line);
	  }
	  InputStream err = p.getErrorStream();
	  BufferedReader brErr = new BufferedReader(new InputStreamReader(err));
	  while ((line=brErr.readLine())!=null) {
	    sdLog.append(line+"\n");
	    Rectangle rect = sdLog.getVisibleRect();
	    //sdLog.paintImmediately(sdLog.getVisibleRect());
	    int a = sdLog.getScrollableUnitIncrement(rect, SwingConstants.VERTICAL, 1);
	    sdLog.scrollRectToVisible(new Rectangle((int) rect.getX(), (int) rect.getY()+a, (int) rect.getWidth(), (int)rect.getHeight()));
	    System.out.println(line);
	    
	  }
	  sdLog.paintImmediately(sdLog.getVisibleRect());
	  
	}
	catch (Exception e) { 
	    JOptionPane.showMessageDialog(this, "An error occured while trying to run executable\n"+e, "Error", JOptionPane.ERROR_MESSAGE);
	    System.out.println("[BRITE ERROR]: An error occured trying to run executable: " +e);
	    
	    BuildTopology.setEnabled(true);
	   
	    return;
	}
	
	//////=======================================================================
	// Uncomment this if you want to run otter right away
	//////=======================================================================
	/*if (ePanel.isOtterFormat()) {
	  String file = ((String)ePanel.ExportLocation.getText()).trim()+".odf"; 
	  Runtime rO= Runtime.getRuntime(); 
	  try { 
	    //HACK for Otter path.  Change for your otter path
	    String runOtter = "/home/anukool/Research/Visualization/otter-0.9/otter -f "+file;
	    System.out.println("[MESSAGE]:  Calling otter: "+runOtter); 
	    Process p = rO.exec(runOtter);
	    
	    InputStream err = p.getErrorStream();
	    BufferedReader brErr = new BufferedReader(new InputStreamReader(err));
	    String line ="";
	    while ((line=brErr.readLine())!=null) 
	    System.out.println(line);
	  } 
	   catch (Exception e) {
	     JOptionPane.showMessageDialog(this, "Could not start Otter\n"+e, "Error", JOptionPane.ERROR_MESSAGE);
	     System.out.println("[BRITE ERROR]: Could not start Otter\n" + e);
	    e.printStackTrace();
	  } 
	} 
	*/
	
	//////=======================================================================
	//////  Comment/Uncomment this if you want/don't want to view the NS tcl output right away
	//////=======================================================================
	/*if (ePanel.isNSFormat()) {
	  String file = ((String)ePanel.ExportLocation.getText()).trim()+".tcl";
	  Runtime rO= Runtime.getRuntime();
	  try {
	      String runOtter = " xedit  "+file+ " &";
	    System.out.println("[MESSAGE]: Opening NS output: "+runOtter); 
	    Process p = rO.exec(runOtter);
	    //InputStream err = p.getErrorStream();
	    //BufferedReader brErr = new BufferedReader(new InputStreamReader(err));
	    //String line ="";
	    //while ((line=brErr.readLine())!=null) 
	    //  System.out.println(line);
	  }
	  catch (Exception e) {
	    JOptionPane.showMessageDialog(this, "Could not start xedit\n"+e, "Error", JOptionPane.ERROR_MESSAGE);
	    System.out.println("[BRITE ERROR]: Could not start xedit\n" + e);
	    e.printStackTrace();
	  }
	}
	*/


	//////=======================================================================
	//////Comment/Uncomment this if you want/don't want to view the DML output right away
	//////=======================================================================
	/*if (ePanel.isDMLFormat()) {
	  String  file = ((String)ePanel.ExportLocation.getText()).trim()+".dml";
	  Runtime  rO= Runtime.getRuntime();
	  try {
	  //
	  String runOtter = "xedit  "+file;
	  System.out.println("[MESSAGE]: Opening DML output: "+runOtter); 
	  Process p = rO.exec(runOtter);
	  
	  //InputStream err = p.getErrorStream();
	  //BufferedReader brErr = new BufferedReader(new InputStreamReader(err));
	  //	    String line ="";
	  //while ((line=brErr.readLine())!=null) 
	  // System.out.println(line);
	  }
	  catch (Exception e) {
	  JOptionPane.showMessageDialog(this, "Could not start xedit (DML)\n"+e, "Error", JOptionPane.ERROR_MESSAGE);
	  System.out.println("[BRITE ERROR]: Could not start xedit (DML)\n" + e);
	  e.printStackTrace();
	  }
	  }
	*/
	
	

    }

    

    public void processWindowEvent(WindowEvent e) {
	super.processWindowEvent(e);
	if (e.getID() == e.WINDOW_CLOSING){    
	    sd.dispose();
	    hPanel.dispose();
	    System.exit(0);
	}
    }


    String ROUTER_TOPOLOGY = "1 Level: ROUTER (IP) ONLY";
    String AS_TOPOLOGY = "1 Level: AS ONLY";
    String TOPDOWN_TOPOLOGY = "2 Level: TOP-DOWN";
    String BOTTOMUP_TOPOLOGY = "2 Level: BOTTOM-UP";
    String[] TopologyTypeData = {AS_TOPOLOGY, ROUTER_TOPOLOGY, TOPDOWN_TOPOLOGY, BOTTOMUP_TOPOLOGY};
    JComboBox TopologyType = new JComboBox(TopologyTypeData);
    
    String JAVAEXE = "Use Java Exe";
    String CPPEXE = "Use C++ Exe";
    String exeData[] = {JAVAEXE, CPPEXE};
    JComboBox ExeChoicesComboBox = new JComboBox(exeData);

    LineBorder lineBorder1 = new LineBorder(java.awt.Color.black);
    JLabel JLabel1 = new JLabel();
    
    JButton logo = new JButton(new ImageIcon("GUI"+System.getProperty("file.separator")+"images"+System.getProperty("file.separator")+
					   "brite4.jpg"));
    JButton BuildTopology = new JButton();
    JButton HelpButton = new JButton();
    JButton LaunchBriana = new JButton();

  StatusDialog sd = new StatusDialog(this);
  JTextArea sdLog;
  private Thread runThread = null;
  public Process p=null;
    
    JTabbedPane JTabbedPane1 = new JTabbedPane();
    ExportPanel ePanel = new ExportPanel();
    HelpPanel hPanel = new HelpPanel(this);  
    AboutPanel aboutPanel = new AboutPanel();
  ASPanel asPanel = new ASPanel();
        RouterPanel rtPanel= new RouterPanel();


  TDPanel tdPanel = new TDPanel(this);
    BUPanel buPanel = new BUPanel(this);
    boolean rtDisabled=false;
    boolean asDisabled=false;
    boolean hDisabled=true;
    
    public static void main(String args[])  {
	GUI.Brite g= new GUI.Brite();
	g.init();
	g.setVisible(true);
	
    }
}












