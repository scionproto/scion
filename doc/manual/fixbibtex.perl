#!/usr/bin/perl -W

$filename = $ARGV[0];

open( FILE, "<$filename" ) || die "Could not open file |$filename|\n";
open( TMPFILE, ">$filename.tmp" ) || die "Could not open file |$filename.tmp|\n";
while ( <FILE> ) {
	if (/(.*)%$/) {
		# Line ends with %
		# Print line without % sign and without newline
		print TMPFILE "$1";
	} else {
		print TMPFILE $_;
	}
}
close( FILE );
close( TMPFILE );
`mv $filename.tmp $filename`;
