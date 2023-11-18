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
from compactdenial import get_resolver, rcode, response

RESOLVER_LIST = ['8.8.8.8', '1.1.1.1']

if __name__ == '__main__':

    PROGNAME = os.path.basename(sys.argv[0])
    parser = argparse.ArgumentParser()
    parser.add_argument("qname", help="DNS query name")
    parser.add_argument("qtype", help="DNS query type")
    parser.add_argument("--response", dest='response', action='store_true',
                        help="Print full response")
    parser.add_argument("--coflag", dest='coflag', action='store_true',
                        help="Send Compact Answers OK EDNS flag")
    ARGS = parser.parse_args()

    RESOLVER = get_resolver(addresses=RESOLVER_LIST, coflag=ARGS.coflag)

    if ARGS.response:
        MSG = response(ARGS.qname, ARGS.qtype, resolver=RESOLVER)
        print(MSG)
        sys.exit(MSG.rcode())

    RC = rcode(ARGS.qname, ARGS.qtype, resolver=RESOLVER)
    print(dns.rcode.to_text(RC))
    sys.exit(RC)
