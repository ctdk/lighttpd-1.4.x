#! /usr/bin/perl -w

use Socket;
my $sock;

if (socket($sock, AF_INET6, SOCK_STREAM, 0)) {
    print "server.use-ipv6 = \"enable\"\n";
}
