# compactdenial
Small library to work with Compact Denial of Existence in DNSSEC.

The Compact Denial of Existence method is defined in the following
Internet draft, which will be published as an RFC in the near
future: https://datatracker.ietf.org/doc/draft-ietf-dnsop-compact-denial-of-existence/

At the current time, Cloudflare and NS1 are known to implement the NXNAME
distinguisher described in the draft that allows precise identification of
non-existent domains.

A small testing script, called "compactrcode" is also included that uses the library:

```
$ compactrcode.py -h
usage: compactrcode.py [-h] [--response] [--resolver RESOLVER]
                       [--server SERVER] [--nsecdebug] [--coflag]
                       qname qtype

positional arguments:
  qname                DNS query name
  qtype                DNS query type

optional arguments:
  -h, --help           show this help message and exit
  --response           Print full response
  --resolver RESOLVER  Resolver IP address to send query to
  --server SERVER      Server IP address to send query to
  --nsecdebug          Decode NSEC records in response
  --coflag             Send Compact Answers OK EDNS flag
```

### Example program usage:

Print effective response code for a given DNS query. In this example,
the response is a Compact Denial style NXDOMAIN disguised as a NOERROR.
The program examines the NXNAME sentinel type in the response's NSEC
record, deduces that the name doesn't actually exist, and returns
NXDOMAIN.

```
$ compactrcode.py nxdomain.cloudflare.net. A
NXDOMAIN
```

Print full response for a given DNS query. The exit code will reflect the effective response code (3, NXDOMAIN in this case).

```
$ compactrcode.py --response nxdomain.cloudflare.net. A
id 21074
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 512
;QUESTION
nxdomain.cloudflare.net. IN A
;ANSWER
;AUTHORITY
cloudflare.net. 1800 IN SOA ns1.cloudflare.net. dns.cloudflare.com. 2324138674 10000 2400 604800 1800
nxdomain.cloudflare.net. 1800 IN NSEC \000.nxdomain.cloudflare.net. RRSIG NSEC TYPE65283
cloudflare.net. 1800 IN RRSIG SOA 13 2 1800 20231120030733 20231118010733 34505 cloudflare.net. Y40wrXU14EsCuL5l6sDUAyh4o277iJ99 RbnUKOO6IDbHUUmYzcwt1OssstfTRkyH SVlgAco16+md7kmpXRSU7Q==
nxdomain.cloudflare.net. 1800 IN RRSIG NSEC 13 3 1800 20231120030733 20231118010733 34505 cloudflare.net. tqE4kDr2Er7Ck/tUUnZszYTiOzROvp7R Lel0iOyRz+0b1m3/VAJKzXBCBNCLl+co QeQdygRBlFdire8PxzKxxA==
;ADDITIONAL

$ echo $?
3
```

### Library Functions in compactdenial.py

```
    get_resolver(addresses=None, lifetime=5, payload=1420, coflag=False)
        Return resolver object configured to use given list of addresses, and
        that sets DO=1, RD=1, AD=1, and EDNS payload for queries to the resolver.

    is_authenticated(msg)
        Does DNS message have Authenticated Data (AD) flag set?

    nsec_type_set(type_bitmaps)
        Return set of RR types present in given NSEC record's type bitmaps.

    nsec_windows(type_bitmaps)
        Iterator that returns info about the next NSEC windowed bitmap.
        Mainly used for debugging or diagnostics.

    query_resolver(qname, qtype, resolver=None)
        Queries a DNS resolver for a given DNS qname and qtype and returns
        the response message.

    query_server(qname, qtype, server, coflag=False)
        Queries a DNS server directly for a given DNS qname and qtype and returns
        the response message. Uses UDP transport with fallback to TCP upon
        truncation.

    rcode(msg, qname)
        Return rcode for given DNS response message. If a compact denial
        style NOERROR response is detected, return NXDOMAIN. Otherwise
        return the actual rcode observed in the DNS reply message.

        A compact denial style NOERROR response is a NXDOMAIN response
        disguised as a NOERROR/NODATA. It is identified by a NOERROR
        response with an empty answer section, and an authority section
        containing an NSEC record matching the query name that contains
        in its type bitmaps field: NSEC, RRSIG, and the NXNAME sentinel type.
        It is sufficent to only check for the presence of NXNAME.
        https://datatracker.ietf.org/doc/draft-ietf-dnsop-compact-denial-of-existence/

DATA
    DEFAULT_QUERY_TIMEOUT = 5
    DEFAULT_UDP_PAYLOAD = 1420
    EDNS_FLAG_CO = 16384
    NXNAME_RRTYPE = 128
    RESOLVER_LIST = ['8.8.8.8', '1.1.1.1']
```
