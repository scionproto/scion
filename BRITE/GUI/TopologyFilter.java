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

import java.io.File;
import javax.swing.*;
import javax.swing.filechooser.*;

public final class TopologyFilter {
  
  public static BRITEFilter brite = new BRITEFilter();
  public static NLANRFilter nlanr = new NLANRFilter();
  public static GTITMFilter gtitm = new GTITMFilter();
  public static GTTSFilter gtts = new GTTSFilter();
  public static InetFilter inet = new InetFilter();
  public static SkitterFilter skitter = new SkitterFilter();
  public static ScanFilter scan = new ScanFilter();
}

final class BRITEFilter extends javax.swing.filechooser.FileFilter {
    
    public boolean accept(File f) {
	if (f.isDirectory())
	    return true;
       
	String fname = f.getName();
	String ext = fname.substring(fname.lastIndexOf('.')+1);
	if (ext!=null) {
	    if (ext.equals("brite"))
		return true;
	    else return false;
	}
	return false;
    }

    public String getDescription() {
	return "BRITE topologies (*.brite)";
    }
    
}


final class NLANRFilter extends javax.swing.filechooser.FileFilter {
    
    public boolean accept(File f) {
	if (f.isDirectory())
	    return true;
       
	String fname = f.getName();
	String ext = fname.substring(fname.lastIndexOf('.')+1);
	if (ext!=null) {
	    if (ext.equals("nlanr"))
		return true;
	    else return false;
	}
	return false;
    }

    public String getDescription() {
	return "NLANR topologies (*.nlanr)";
    }
    
}


final class SkitterFilter extends javax.swing.filechooser.FileFilter {
    
    public boolean accept(File f) {
	if (f.isDirectory())
	    return true;
       
	String fname = f.getName();
	String ext = fname.substring(fname.lastIndexOf('.')+1);
	if (ext!=null) {
	    if (ext.equals("skitter"))
		return true;
	    else return false;
	}
	return false;
    }

    public String getDescription() {
	return "Skitter Artsdump (*.skitter)";
    }
    
}


final class ScanFilter extends javax.swing.filechooser.FileFilter {
    
    public boolean accept(File f) {
	if (f.isDirectory())
	    return true;
       
	String fname = f.getName();
	String ext = fname.substring(fname.lastIndexOf('.')+1);
	if (ext!=null) {
	    if (ext.equals("scan"))
		return true;
	    else return false;
	}
	return false;
    }

    public String getDescription() {
	return "SCAN snapshots (*.scan)";
    }
    
}



final class GTITMFilter extends javax.swing.filechooser.FileFilter {
    public boolean accept(File f) {
	if (f.isDirectory())
	    return true;
	
	String fname = f.getName();
	String ext = fname.substring(fname.lastIndexOf('.')+1);
	if (ext!=null) {
	    if (ext.equals("gtitm"))
		return true;
	    else return false;
	}
	return false;
    }
    
    public String getDescription() {
	return "GTITM topologies (*.gtitm)";
    }


}

final class GTTSFilter extends javax.swing.filechooser.FileFilter {
    public boolean accept(File f) {
	if (f.isDirectory())
	    return true;
	
	String fname = f.getName();
	String ext = fname.substring(fname.lastIndexOf('.')+1);
	if (ext!=null) {
	    if (ext.equals("gtts"))
		return true;
	    else return false;
	}
	return false;
    }
    
    public String getDescription() {
	return "GTITM transit-stub (*.gtts)";
    }
}


final class InetFilter extends javax.swing.filechooser.FileFilter {
    public boolean accept(File f) {
	if (f.isDirectory())
	    return true;
	
	String fname = f.getName();
	String ext = fname.substring(fname.lastIndexOf('.')+1);
	if (ext!=null) {
	    if (ext.equals("inet"))
		return true;
	    else return false;
	}
	return false;
    }
    
    public String getDescription() {
	return "Inet topologies (*.inet)";
    }


}



