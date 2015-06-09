#----------------------------- MAKEFILE For Java BRITE

JFLAGS=-O -classpath ../:.

all:
	javac ${JFLAGS} Main/*.java Graph/*.java Model/*.java Import/*.java Export/*.java Util/*.java

javadoc:
	rm -rf javadoc; mkdir javadoc; javadoc -d javadoc/ Main Topology Model Graph Import Export Util 

clean: 
	rm -f Main/*.class Export/*.class Graph/*.class Util/*.class Topology/*.class Model/*.class Util/*.class Import/*.class 
	rm -f Main/*~ Export/*~ Import/*~ Graph/*~ Util/*~ Topology/*~ Model/*~ Util/*~
	rm -rf javadoc
