#BRITE Makefile.  April 2002

all:	c++ java exe  
 
clean:  c++clean javaclean guiclean	

c++:
	@if test -f C++/Makefile; then\
	 (cd C++; make) ; \
	 (make gui);\
	fi

c++clean:
	@if test -f C++/Makefile; then\
	 (cd C++; make clean); \
	fi

java:
	@if test -f Java/Makefile; then \
	  (cd Java; make) ; \
	  (make gui); \
	fi

javaclean:
	@if test -f Java/Makefile; then\
	  (cd Java; make clean) ;\
	fi

gui:
	@if test -f GUI/Makefile; then \
	 (cd GUI; make) ; \
	fi

guiclean: 
	@if test -f GUI/Makefile; then\
	  (cd GUI; make clean ); \
	fi

exe:
	@echo "#!/bin/sh" > brite
	@echo "" >> brite
	@echo "java -Xmx256M -classpath Java/:. GUI.Brite" >> brite
	@chmod +x brite
