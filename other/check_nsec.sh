#!/bin/sh
#
# A test script
#

ZONE=${1:-sfdcsd.net.}
QNAME=${2:-nxd.ent1.sfdcsd.net.}

dig +short $ZONE NS | sortdomainnames.py | while read nsname
do
    for address in `dig +short $nsname AAAA` `dig +short $nsname A`
    do
	echo "###" $nsname $address
	dig @$address +dnssec +noall +authority $QNAME | \
	    awk '$4 == "NSEC"'
	echo ""
    done
done
