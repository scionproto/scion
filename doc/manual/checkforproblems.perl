#!/usr/bin/perl -W

while (<>) {
	if (/pubic/i) {
		printwarning( "PUBIC" );
	}
	if (/dependant/i) {
		printwarning( "DEPENDANT" );
	}
}

sub printwarning{
	$s = $_[0];
	print "****************************************\n";
	print "****************************************\n";
	print "***      Warning, $s occurs!      ***\n";
	print "****************************************\n";
	print "****************************************\n";
	exit( 1 );
}
