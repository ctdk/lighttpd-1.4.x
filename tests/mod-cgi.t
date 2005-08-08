#! /usr/bin/perl -w
BEGIN {
    # add current source dir to the include-path
    # we need this for make distcheck
   (my $srcdir = $0) =~ s#/[^/]+$#/#;
   unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 9;
use LightyTest;

my $tf = LightyTest->new();
my $t;
    
ok($tf->start_proc == 0, "Starting lighttpd") or die();

# mod-cgi
#
$t->{REQUEST}  = ( <<EOF
GET /cgi.pl HTTP/1.0
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok($tf->handle_http($t) == 0, 'perl via cgi');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl/foo HTTP/1.0
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/cgi.pl' } );
ok($tf->handle_http($t) == 0, 'perl via cgi + pathinfo');

$t->{REQUEST}  = ( <<EOF
GET /cgi-pathinfo.pl/foo HTTP/1.0
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/foo' } );
ok($tf->handle_http($t) == 0, 'perl via cgi + pathinfo');

$t->{REQUEST}  = ( <<EOF
GET /nph-status.pl HTTP/1.0
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok($tf->handle_http($t) == 0, 'NPH + perl, Bug #14');

$t->{REQUEST} = ( <<EOF
GET /get-header.pl?GATEWAY_INTERFACE HTTP/1.0
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'CGI/1.1' } );
ok($tf->handle_http($t) == 0, 'cgi-env: GATEWAY_INTERFACE');

$t->{REQUEST}  = ( <<EOF
GET /get-header.pl?HTTP_XX_YY123 HTTP/1.0
xx-yy123: foo
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'foo' } );
ok($tf->handle_http($t) == 0, 'cgi-env: quoting headers with numbers');

$t->{REQUEST}  = ( <<EOF
GET /get-header.pl?HTTP_HOST HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
ok($tf->handle_http($t) == 0, 'cgi-env: HTTP_HOST');


ok($tf->stop_proc == 0, "Stopping lighttpd");

