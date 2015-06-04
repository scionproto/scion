# Makefile for BRITE 2.1 C++ Generation Engine

CC = g++ -Wall -Wno-deprecated
CFLAGS = -o 
MODELS=./Models

cppgen:  BriteMain.o  Node.o Edge.o Graph.o Topology.o Util.o Parser.o \
	Parser.o Model.o RouterModel.o ASModel.o RouterWaxmanModel.o \
	RouterBarabasiAlbertModel.o RouterBarabasiAlbertModel-1.o \
	RouterBarabasiAlbertModel-2.o RouterGLPModel.o\
	ASWaxmanModel.o ASBarabasiAlbertModel.o \
	ASBarabasiAlbertModel-1.o ASBarabasiAlbertModel-2.o ASGLPModel.o\
	TopDownHierModel.o BottomUpHierModel.o ImportedFileModel.o
	$(CC) $(CFLAGS) cppgen BriteMain.o Graph.o Topology.o Node.o \
		Edge.o Util.o Parser.o Model.o RouterModel.o \
		ASModel.o RouterWaxmanModel.o RouterBarabasiAlbertModel.o \
		RouterBarabasiAlbertModel-1.o RouterBarabasiAlbertModel-2.o \
		RouterGLPModel.o ASWaxmanModel.o ASBarabasiAlbertModel.o \
		ASBarabasiAlbertModel-1.o ASBarabasiAlbertModel-2.o ASGLPModel.o\
		TopDownHierModel.o BottomUpHierModel.o ImportedFileModel.o -lm -g

BriteMain.o: BriteMain.cc Brite.h Models/Model.h
	$(CC) -c BriteMain.cc -g

Node.o: Node.cc Node.h
	$(CC) -c Node.cc -g

Edge.o: Edge.cc Edge.h
	$(CC) -c Edge.cc -g

Util.o: Util.cc Util.h
	$(CC) -c Util.cc -g

Graph.o: Graph.cc Graph.h
	$(CC) -c Graph.cc -g

Topology.o: Topology.cc Topology.h
	$(CC) -c Topology.cc -g

Parser.o: Parser.cc Parser.h
	$(CC) -c Parser.cc -g

Model.o: $(MODELS)/Model.cc $(MODELS)/Model.h
	$(CC) -c $(MODELS)/Model.cc -g

RouterModel.o: \
	$(MODELS)/RouterModel.cc $(MODELS)/RouterModel.h
	$(CC) -c $(MODELS)/RouterModel.cc -g

RouterWaxmanModel.o: \
	$(MODELS)/RouterWaxmanModel.cc $(MODELS)/RouterWaxmanModel.h 
	$(CC) -c $(MODELS)/RouterWaxmanModel.cc -g

RouterBarabasiAlbertModel.o: \
	$(MODELS)/RouterBarabasiAlbertModel.cc $(MODELS)/RouterBarabasiAlbertModel.h
	$(CC) -c $(MODELS)/RouterBarabasiAlbertModel.cc -g

RouterBarabasiAlbertModel-1.o: \
	$(MODELS)/RouterBarabasiAlbertModel-1.cc $(MODELS)/RouterBarabasiAlbertModel-1.h
	$(CC) -c $(MODELS)/RouterBarabasiAlbertModel-1.cc -g

RouterBarabasiAlbertModel-2.o: \
	$(MODELS)/RouterBarabasiAlbertModel-2.cc $(MODELS)/RouterBarabasiAlbertModel-2.h
	$(CC) -c $(MODELS)/RouterBarabasiAlbertModel-2.cc -g

RouterGLPModel.o: \
	$(MODELS)/RouterGLPModel.cc $(MODELS)/RouterGLPModel.h
	$(CC) -c $(MODELS)/RouterGLPModel.cc -g

ASModel.o: \
	$(MODELS)/ASModel.cc $(MODELS)/ASModel.h
	$(CC) -c $(MODELS)/ASModel.cc -g

ASWaxmanModel.o: \
	$(MODELS)/ASWaxmanModel.cc $(MODELS)/ASWaxmanModel.h 
	$(CC) -c $(MODELS)/ASWaxmanModel.cc -g

ASBarabasiAlbertModel.o: \
	$(MODELS)/ASBarabasiAlbertModel.cc $(MODELS)/ASBarabasiAlbertModel.h
	$(CC) -c $(MODELS)/ASBarabasiAlbertModel.cc -g

ASBarabasiAlbertModel-1.o: \
	$(MODELS)/ASBarabasiAlbertModel-1.cc $(MODELS)/ASBarabasiAlbertModel-1.h
	$(CC) -c $(MODELS)/ASBarabasiAlbertModel-1.cc -g

ASBarabasiAlbertModel-2.o: \
	$(MODELS)/ASBarabasiAlbertModel-2.cc $(MODELS)/ASBarabasiAlbertModel-2.h
	$(CC) -c $(MODELS)/ASBarabasiAlbertModel-2.cc -g

ASGLPModel.o: \
	$(MODELS)/ASGLPModel.cc $(MODELS)/ASGLPModel.h
	$(CC) -c $(MODELS)/ASGLPModel.cc -g

TopDownHierModel.o: \
	$(MODELS)/TopDownHierModel.cc $(MODELS)/TopDownHierModel.h
	$(CC) -c $(MODELS)/TopDownHierModel.cc  -g	

BottomUpHierModel.o: \
	$(MODELS)/BottomUpHierModel.cc $(MODELS)/BottomUpHierModel.h
	$(CC) -c $(MODELS)/BottomUpHierModel.cc  -g	

ImportedFileModel.o: \
	$(MODELS)/ImportedFileModel.cc $(MODELS)/ImportedFileModel.h
	$(CC) -c $(MODELS)/ImportedFileModel.cc  -g	

clean:
	rm -f *.o *~
	rm -f brite cppgen
