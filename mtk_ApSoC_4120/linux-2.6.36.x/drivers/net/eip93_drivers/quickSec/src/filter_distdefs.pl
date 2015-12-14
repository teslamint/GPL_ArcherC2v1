#!/usr/bin/perl -w 

while (<>) 
{
    chomp;
    s/\s+//;
    $pattern = $_;
    
    if (/^SSHDIST_/)
    {
	print "Undefining $pattern\n";
	
	open DISTDEFS, "sshdistdefs.h"
	or  die "Cannot open sshdistdefs.h";
	
	open OUT, ">sshdistdefs-tmp.h"
	    or  die "Cannot open sshdistdefs-tmp.h";
	
	while (<DISTDEFS>)
	{
	    chomp;
	    
	    if (/^\#define \b($pattern)\b/)
	    {
		s/define/undef/;
	    }
	    
	    print OUT "$_\n";
	}	
	
	close OUT;    
	close DISTDEFS;
	rename "sshdistdefs-tmp.h", "sshdistdefs.h";
    }
}
    
