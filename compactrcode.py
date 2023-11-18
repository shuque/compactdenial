#!/usr/bin/env python3

"""
compactrcode.py: Compact Denial enhanced rcode function.

Query given DNS name and type, and return the response code.
If a compact denial of existence style NODATA response is returned,
detect whether it is actually a non-existent domain and return
NXDOMAIN instead.

Author: Shumon Huque
"""


import os
import sys
import argparse
import dns.rcode
from compactdenial import get_resolver, rcode, query_resolver, query_server, nsec_windows

RESOLVER_LIST = ['8.8.8.8', '1.1.1.1']


def decode_nsec_bitmaps(msg):
    """Decode NSEC record bitmaps"""
    for rrset in msg.authority:
        if  rrset.rdtype not in  [dns.rdatatype.NSEC, dns.rdatatype.NSEC3]:
            continue
        for rdata in rrset.to_rdataset():
            print(rrset.name,
                  rrset.ttl,
                  dns.rdataclass.to_text(rrset.rdclass),
                  dns.rdatatype.to_text(rrset.rdtype),
                  rdata)
            for (window, bitmap, bitnumbers) in nsec_windows(rdata.windows):
                start_rr = 256 * window
                print(f'  Window {window}, StartRR {start_rr}:')
                print(f"    len={len(bitmap)} {bitmap}")
                print(f"    Bits: {bitnumbers}")
                rrtypes = [start_rr + x for x in bitnumbers]
                print(f"    RRs : {rrtypes}")


def get_response(args):
    """Get DNS response message"""

    if args.server:
        return query_server(args.qname, args.qtype, args.server, coflag=args.coflag)

    resolver = get_resolver(addresses=RESOLVER_LIST, coflag=args.coflag)
    return query_resolver(args.qname, args.qtype, resolver=resolver)


if __name__ == '__main__':

    PROGNAME = os.path.basename(sys.argv[0])
    parser = argparse.ArgumentParser()
    parser.add_argument("qname", help="DNS query name")
    parser.add_argument("qtype", help="DNS query type")
    parser.add_argument("--response", dest='response', action='store_true',
                        help="Print full response")
    parser.add_argument("--server", dest='server',
                        help="Server IP address to send query to")
    parser.add_argument("--nsecdebug", dest='nsecdebug', action='store_true',
                        help="Decode NSEC records in response")
    parser.add_argument("--coflag", dest='coflag', action='store_true',
                        help="Send Compact Answers OK EDNS flag")
    ARGS = parser.parse_args()

    MSG = get_response(ARGS)
    RC = rcode(MSG, ARGS.qname)

    if ARGS.response:
        print(MSG)
    elif ARGS.nsecdebug:
        decode_nsec_bitmaps(MSG)
    else:
        print(dns.rcode.to_text(RC))
    sys.exit(RC)
