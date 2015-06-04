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
/*  Author:     Alberto Medina                                              */
/*              Anukool Lakhina                                             */
/*  Title:     BRITE: Boston university Representative Topology gEnerator   */
/*  Revision:  2.0         4/02/2001                                        */
/****************************************************************************/
#ifndef NODE_H
#define NODE_H
#pragma interface

#include "Util.h"
#include "Graph.h"
#include "Topology.h"

class Topology;
class NodeConf;
class Graph;
class Edge;

class Node {

 public:

  Node(int i);
  Node(NodeConf* info);

  int GetId() { return nodeId;  }
  int GetAddr() { return nodeAddr; }
  int GetInDegree() { return inDegree; }
  int GetOutDegree() { return outDegree; }
  Color GetColor() { return nodeColor; }
  NodeConf* GetNodeInfo() { return nodeInfo; }
  
  void SetId(int id) { nodeId = id;  }
  void SetAddr(int addr) { nodeAddr = addr; }
  void SetInDegree(int degree) { inDegree = degree; }
  void SetOutDegree(int degree) { outDegree = degree; }
  void SetColor(Color col) { nodeColor = col; }
  void SetNodeInfo(NodeConf*  info) { nodeInfo = info; }
  /* SPRINT */
  void AddIncEdge(Edge* edge);
  Edge* GetEdge(int v);

 private:

  int nodeId;
  int nodeAddr;
  int inDegree;
  int outDegree;
  Color nodeColor;
  NodeConf* nodeInfo;
  /* SPRINT */
  list<Edge*> incEdges;

};

// to derive from it specific node types
class NodeConf {

 public:

  enum NodeType { AS_NODE = 1, RT_NODE = 2 };
  double GetCost() { return cost; }
  void SetCost(double c) { cost = c; }
  string GetName() { return name; }
  void SetName(string s) { name = s; }
  NodeType GetNodeType() { return type; }
  void SetNodeType(NodeType t) { type = t; }
  double GetCoordX() { return x; }
  double GetCoordY() { return y; }
  double GetCoordZ() { return z; }
  void SetCoord(double xval, double yval, double zval) {
    x = xval;
    y = yval;
    z = zval;
  }

 private:
  
  string name;
  double cost;
  NodeType type;
  double x;
  double y;
  double z;

};


class RouterNodeConf : public NodeConf {

 public:

  RouterNodeConf();
  enum RouterNodeType { RT_NONE, RT_LEAF, RT_BORDER, RT_STUB, RT_BACKBONE };
  RouterNodeType GetRouterType() { return rttype; }
  void SetRouterType(RouterNodeType t) { rttype = t; }
  int GetASId() { return ASid; }
  void SetASId(int i) { ASid = i; }

 private:
  
  RouterNodeType rttype;
  int ASid;

};

class ASNodeConf : public NodeConf {

 public:

  enum ASNodeType {AS_NONE, AS_LEAF, AS_STUB, AS_BORDER, AS_BACKBONE};
  ASNodeConf();
  ~ASNodeConf();
  Topology* GetTopology() { return t; }
  void SetTopology(Topology* top, int asid);
  ASNodeType GetASType() { return astype; }
  void SetASType(ASNodeType t) { astype = t; }
  int GetASId() { return ASid; }
  void SetASId(int i) { ASid = i; }

 private:

  Topology* t;
  ASNodeType astype;
  int ASid;

};

#endif /* NODE_H */
