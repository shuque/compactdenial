#!/usr/bin/env python3

"""
compactdenial.py
Library of functions to work with Compact Denial of Existence.

Author: Shumon Huque
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.rcode

# NXNAME pseudo type code point (ENT type has been retired).
# After the RFC is published, an official RR type code value will be
# assigned and the following line will need to be updated.
NXNAME_RRTYPE = 65283

# Compact Answer OK (CO) EDNS Header Flag
EDNS_FLAG_CO = 0x4000

# Resolver List. Note: to correctly determine Compact Denial of Existence
# style NXDOMAIN, these need to be DNSSEC validating resolvers.
RESOLVER_LIST = ['8.8.8.8', '1.1.1.1']


def get_resolver(addresses=None, lifetime=5, payload=1420, coflag=False):
    """
    Return resolver object configured to use given list of addresses, and
    that sets DO=1, RD=1, AD=1, and EDNS payload for queries to the resolver.
    """

    ednsflags = dns.flags.DO
    if coflag:
        ednsflags |= EDNS_FLAG_CO

    resolver = dns.resolver.Resolver()
    resolver.set_flags(dns.flags.RD | dns.flags.AD)
    resolver.use_edns(edns=0, ednsflags=ednsflags, payload=payload)
    resolver.lifetime = lifetime
    if addresses is not None:
        resolver.nameservers = addresses
    return resolver


def is_authenticated(msg):
    """Does DNS message have Authenticated Data (AD) flag set?"""
    return msg.flags & dns.flags.AD == dns.flags.AD


def nsec_type_set(type_bitmaps):
    """
    Return set of RR types present in given NSEC record's type bitmaps.
    """
    type_set = set()
    for (window, bitmap) in type_bitmaps:
        for i, _ in enumerate(bitmap):
            for j in range(0, 8):
                if bitmap[i] & (0x80 >> j):
                    rrtype = window * 256 + i * 8 + j
                    type_set.add(rrtype)
    return type_set


def rcode(qname, qtype, resolver=None):
    """
    Return rcode for given DNS qname and qtype. If a compact denial
    style NOERROR response is detected, return NXDOMAIN. Otherwise
    return the actual rcode observed in the DNS reply message.

    A compact denial style NOERROR response is a NXDOMAIN response
    disguised as a NOERROR/NODATA. It is identified by a DNSSEC
    authenticated (AD=1) NOERROR response with an empty answer
    section, and an authority section containing an NSEC record
    matching the query name that contains in its type bitmaps field:
    NSEC, RRSIG, and the NXNAME sentinel type. It is sufficent to
    only check the presence of NXNAME.
    https://datatracker.ietf.org/doc/draft-ietf-dnsop-compact-denial-of-existence/
    """

    if not isinstance(qname, dns.name.Name):
        qname = dns.name.from_text(qname)
    msg = response(qname, qtype, resolver)

    if is_authenticated(msg) and (
            msg.rcode() == dns.rcode.NOERROR and not msg.answer):
        for rrset in msg.authority:
            if rrset.name != qname:
                continue
            if  rrset.rdtype != dns.rdatatype.NSEC:
                continue
            for rdata in rrset.to_rdataset():
                if NXNAME_RRTYPE in nsec_type_set(rdata.windows):
                    return dns.rcode.NXDOMAIN
                return msg.rcode()
    return msg.rcode()


def response(qname, qtype, resolver=None):
    """
    Return DNS response message for a given DNS qname and qtype.
    """

    if resolver is None:
        resolver = get_resolver()

    if not isinstance(qname, dns.name.Name):
        qname = dns.name.from_text(qname)
    try:
        msg = resolver.resolve(qname, qtype, raise_on_no_answer=False).response
    except dns.resolver.NXDOMAIN as error:
        return error.response(qname)
    return msg
