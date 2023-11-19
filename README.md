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
usage: compactrcode.py [-h] [--response] [--server SERVER] [--nsecdebug]
                       [--coflag]
                       qname qtype

positional arguments:
  qname            DNS query name
  qtype            DNS query type

optional arguments:
  -h, --help       show this help message and exit
  --response       Print full response
  --server SERVER  Server IP address to send query to
  --nsecdebug      Decode NSEC records in response
  --coflag         Send Compact Answers OK EDNS flag
```

### Example usage:

Print effective response code for a given DNS query:
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

Shumon Huque
