#!/usr/bin/perl -Tw

use strict;
use CGI;

my($cgi) = new CGI;

#增加-charset=>'UTF-8',-type=>''，是为了去除页面出现的一串字符：Content-Type: text/html; charset=ISO-8859-1
print $cgi->header(-charset=>'UTF-8', -type=>'');
my($color) = "blue";
$color = $cgi->param('color') if defined $cgi->param('color');

print $cgi->start_html(-title => uc($color),
                       -BGCOLOR => $color);
print $cgi->h1("This is $color");
print $cgi->h2("Champion is the best, right?");
print $cgi->end_html;
