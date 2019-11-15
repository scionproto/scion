SHELL=/bin/bash

all:
	java -Xmx500M -cp "/usr/local/lib/antlr-4.7.1-complete.jar:$CLASSPATH" org.antlr.v4.Tool -Dlanguage=Go -o path_predicate -package path_predicate PathPredicate.g4
	java -Xmx500M -cp "/usr/local/lib/antlr-4.7.1-complete.jar:$CLASSPATH" org.antlr.v4.Tool -Dlanguage=Go -o traffic_class -package traffic_class TrafficClass.g4
