#!/usr/bin/perl -w
###########
# SonicWALL Nagios VPN check
# Modified by Jeff Roberson
# Based on the Cacti Sonicwall VPN Traffic Script
# Created by Ken Nerhood
# 
# based on the lan2lantraffic.pl script by Dan Brummer
#
# This script will query the names of the active VPN's on the SonicWall
# Then test to see if the given name is listed.  If it is, it will
# return OK, otherwise it will return CRITICAL
#
# Usage:
#   check_vpn.pl host community vpn_name
#   check_vpn.pl host community LIST_ALL_VPNS
#
#    DEVICE is the IP address of the PeerGateway of the tunnel you want
###########
use strict;

use Getopt::Long qw(:config no_ignore_case);
use Net::SNMP;
my ($session, $error, %datatable, $oid, $key, $host, $community, $vpn, $HELP, $result);

my $usage = <<EOF;

This plug tests to see if a given SonicWALL VPN is active or not.

Usage: check_vpn -H|host -C|community -V|vpn
-H, --host=SonicWALL 
  IP address of the SonicWALL creating the VPN
-c, --community
  SNMP community name used to list the active VPN's
-V,--vpn
  The name of the VPN to check for

Note: SNMP must be active on the SonicWALL device.

EOF

my %STATUSCODE = (  'OK'       => '0',
                    'WARNING'  => '1',
                    'CRITICAL' => '2',
		    'UNKNOWN'  => '3');

$result = GetOptions("H|host=s"	=> \$host,
		"C|commuinty=s"	=> \$community,
		"V|vpn=s"	=> \$vpn,
		"h|help"	=> \$HELP,
		);

# Set OID variables
my $sonicSAStatPeerGateway	= ".1.3.6.1.4.1.8741.1.3.2.1.1.1.2";
my $sonicSAStatDecryptByteCount	= ".1.3.6.1.4.1.8741.1.3.2.1.1.1.11";
my $sonicSAStatEncryptByteCount	= ".1.3.6.1.4.1.8741.1.3.2.1.1.1.9";
my $sonicSAStatUserName		= ".1.3.6.1.4.1.8741.1.3.2.1.1.1.14";

if ($HELP) {
	print $usage;
	exit($STATUSCODE{'UNKNOWN'});
}

if (!($host && $community)) {
	print "ERROR: Missing SNMP community string.";
	print $usage;
	exit($STATUSCODE{'UNKNOWN'});
}

if (!($host && $vpn)) {
        print "ERROR: Missing VPN name.";
        print $usage;
        exit($STATUSCODE{'UNKNOWN'});
}

# Create SNMP Session

($session, $error) = Net::SNMP->session(-hostname=>$host,-community=>$community,-port=>161);
die "session error: $error" unless ($session);

# Walk sonicSAStatPeerGateway for list of active session OIDs

$result = $session->get_table(-baseoid => $sonicSAStatPeerGateway);
die "request error: ".$session->error unless (defined $result);

# Grab the oids and stick it into an array (ghetto)
my @indexoids = $session->var_bind_names;

# Loop through the oid array and make a seperate request to get the data (even more ghetto)
foreach $oid (@indexoids){

	# Split the full OID to get the index
	my @splits = split($sonicSAStatPeerGateway,$oid);

	# Set index var
	my $dataindex = $splits[1];

	# Grab a hash of the IP address from the OID
	my $getdata = $session->get_request($oid);

	# Take the oid index and the returned value and create a hash
	# This is your datatable with index => ipaddress
	$datatable{$dataindex} = $getdata->{$oid};

}

foreach $key (sort keys (%datatable)){
	my $namedata = $session->get_request($sonicSAStatUserName.$key);
	my $name = $namedata->{$sonicSAStatUserName.$key};
	if ($vpn eq "LIST_ALL_VPNS") {
		print $name . "\n";
	} elsif ($name eq $vpn) {
		print "VPN $vpn is alive.";
		exit($STATUSCODE{'OK'});
	}
}

if ($vpn eq "LIST_ALL_VPNS") {
	exit($STATUSCODE{'UNKNOWN'});
}
# Close SNMP session

$session->close;

print "VPN $vpn is DOWN";
exit($STATUSCODE{'CRITICAL'});

