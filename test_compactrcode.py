#!/usr/bin/env python3

"""
Unit tests for compactdenial.py
"""

import unittest
import dns.rcode
from compactdenial import RESOLVER_LIST, get_resolver, rcode


class TestRcodes(unittest.TestCase):

    def setUp(self):
        self.resolver = get_resolver(addresses=RESOLVER_LIST)

    def test_null_resolver(self):
        qname = 'blahblah.salesforce.com'
        qtype = 'A'
        self.assertEqual(rcode(qname, qtype), dns.rcode.NXDOMAIN)

    def test_compact_nxdomain_ns1(self):
        qname = 'nxd.ent1.sfdcsd.net'
        qtype = 'A'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NXDOMAIN)

    def test_compact_nxdomain_cloudflare(self):
        qname = 'nxdomain.cloudflare.net'
        qtype = 'A'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NXDOMAIN)

    def test_compact_ent_ns1(self):
        qname = 'ent1.sfdcsd.net'
        qtype = 'A'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NOERROR)

    def test_compact_answer_ns1(self):
        qname = 'documentforce.com'
        qtype = 'SOA'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NOERROR)

    def test_normal_nxdomain(self):
        qname = 'foobarnxd1234.salesforce.com'
        qtype = 'A'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NXDOMAIN)

    def test_normal_nodata(self):
        qname = 'salesforce.com'
        qtype = 'PTR'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NOERROR)

    def test_normal_answer(self):
        qname = 'salesforce.com'
        qtype = 'SOA'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NOERROR)

    def test_unsigned_nxdomain(self):
        qname = 'blahblah.z.salesforce.com'
        qtype = 'A'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NXDOMAIN)

    def test_unsigned_nodata(self):
        qname = 'z.salesforce.com'
        qtype = 'PTR'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NOERROR)

    def test_unsigned_answer(self):
        qname = 'z.salesforce.com'
        qtype = 'SOA'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NOERROR)

    def test_normal_ent(self):
        qname = 'visual.force.com'
        qtype = 'A'
        self.assertEqual(rcode(qname, qtype, self.resolver), dns.rcode.NOERROR)


if __name__ == '__main__':
    unittest.main()
