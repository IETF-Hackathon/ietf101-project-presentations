# Code written for the DoH ([DNS-over-HTTPS](https://datatracker.ietf.org/wg/doh)) work during the hackathon

All the code here work with HTTP/2 and TLS.

## Servers

[doh-proxy](https://github.com/facebookexperimental/doh-proxy/) written
in Python, and using [dnspython](http://www.dnspython.org/) saw
fixes and improvments.

[Tony Finch's proxy](https://fanf.dreamwidth.org/123507.html), as a
Nginx module in Lua. doh101 is available [at Github](https://github.com/fanf2/doh101) and [at his Gitlab](https://dotat.at/cgi/git/doh101.git).

[Presentation](https://datatracker.ietf.org/meeting/101/materials/slides-101-hackathon-sessa-dnsproxy-local-dns-over-http-private-resolver) of [DNSproxy](https://github.com/fantuz/DNSProxy)

`quart-doh.py` is a server written in Python with the
[Quart framework](https://gitlab.com/pgjones/quart) for HTTP/2. It
uses the [dnspython library](http://www.dnspython.org/) to send the request to a full resolver. You
can start it with `./quart-doh.py -r YOURESOLVER` (`-h` for other
options. With `-c`, you have a checking mode, for interoperability testing.

Work under way for [CoreDNS](https://coredns.io/)

## Clients

[JavaScript code](https://github.com/pusateri/doh-client) using the
[dns-packet library](https://github.com/mafintosh/dns-packet). A test
Web page is [under development](https://github.com/pusateri/doh-webpack).

Firefox has now
[a DoH client](https://gist.github.com/bagder/5e29101079e9ac78920ba2fc718aceec)

`dns-client.py` is a Python client using the
[pycurl](http://pycurl.io/), which itself depends on
[pycurl](https://curl.haxx.se/libcurl/). 

`doh-nghttp.c` is a C client, using the
[nghttp2 asynchronous HTTP/2 library](https://nghttp2.org/) and the
[getdns library](https://getdnsapi.net) to encode and decode DNS
messages. You can compile it with `cc -c doh-nghttp.c` and link it
with `cc -odoh-nghttp  doh-nghttp.o getdns-git/src/parseutil.o -lnghttp2 -lhttp_parser -levent -lssl -lcrypto -levent_openssl -lgetdns`.

## Libraries

Work is under way for the C library [getdns](https://getdnsapi.net).
The development branch for this work is [here](https://github.com/wtoorop/getdns/tree/features/upstream-management-doh).
It relies on the [new upstream server management](https://github.com/wtoorop/getdns/tree/features/upstream-management) code.
Once finished, this is how DoH upstreams can be configured in a [Stubby](https://dnsprivacy.org/wiki/x/JYAT) YAML configuration file:
```
# Specify the list of upstream recursive name servers to send queries to
upstream_recursive_servers:
# Manu Bretelle's DNS over HTTPS server:
  - uri: "https://dns.dnsoverhttps.net/dns-query"
# The google DNS over HTTPS server:
  - uri: "https://dns.google.com/experimental"
# The cloudflare DNS over HTTPS server:
  - uri: "https://dns.cloudflare.com/.well-known/dns-query"
# The Stephane Bortzmeyer's DNS over HTTPS server:
  - uri: "https://dns.bortzmeyer.fr"
# The quad9 DNS over TLS server
  - name: "dns.quad9.net"
```

[Go DNS](https://miek.nl/2014/august/16/go-dns-package/) now has DoH.
[The plan](https://miek.nl/2018/february/19/ietf-101-dns-hackathon/)
and [the report](https://www.ietf.org/mail-archive/web/doh/current/msg00285.html)

## Public DoH servers

It is interesting to know that each uses a different code base.

* https://dns.dnsoverhttps.net/dns-query 
* https://dns.google.com/experimental
* https://dns.cloudflare.com/.well-known/dns-query
* https://dns.bortzmeyer.fr (ephemeral / temporary)
* https://vm1.dev.dns.cam.ac.uk/doh (v6 only, ephemeral / temporary)

## Ideas for interoperability testing

Client side tests are tests that would be run from the client to test the server conformance

Server side tests are errors that would be logged if a client was to send invalid content

### Client side

* correct MIME type
* return code should be 415 when the content type is invalid
* return code should be 405 when the method is not accepted (check that Allow header is set). What about HEAD? if the server does not accept GET, then HEAD is pointless . doh-proxy fail the HEAD handling: https://github.com/facebookexperimental/doh-proxy/issues/37
* return code should be 406 when the content type is not accepted by the server: does the server returns a list of accepted content type?
* does server supports GET
* does server supports POST
* Invalid certificates should be rejected
* "intelligent" use of the cache-control and expires headers
* send Base64 with padding

### Server Side

* ID set to 0
* if GET, check that ct= and dns= exist and that ct= has a proper value
* check the MIME type

### Software

[Manu Bretelle's test system](https://github.com/chantra/doh-proxy/tree/integration_tests_). To
install dependencies: `pip install -e .[integration_tests]`. To run
the test: `PYTHONPATH=. python3 ./dohproxy/integration.py --domain
dohserver.example.com`. See `-h` for more options.
        
This is using the unittest framework and basically will print the result for individual tests and then spit out the exceptions.
    
Also, the `test-servers.py` (requires dnspython and pycurl) tests several servers:

```./test-servers.py www.ietf.org  https://dns.dnsoverhttps.net/dns-query  https://dns.google.com/experimental https://dns.cloudflare.com/.well-known/dns-query https://dns.bortzmeyer.fr  
https://dns.dnsoverhttps.net/dns-query
WARNING: Impossible content type requested and accepted

https://dns.google.com/experimental
ERROR: HTTP error in reply to HEAD 400
WARNING: Impossible content type requested and accepted

https://dns.cloudflare.com/.well-known/dns-query
INFO: GET not implemented
INFO: HEAD not implemented
WARNING: Impossible content type requested and accepted

https://dns.bortzmeyer.fr
WARNING: Impossible content type requested and accepted
```

# Questions/notes about the current draft

Wire format specification should explicitly say that length preambule
is not part of the DNS wireformat blob, just to be explicit? No
implementor included it (it is useless for HTTP).

Should we use
[GET, POST or both?](https://mailarchive.ietf.org/arch/msg/doh/-2AtS1o32YkoZvzo6UXU0qDx3RY)
(see the Cloudflare test above)

# Bug fixes

As always during a hackathon, some bugs were discovered in the
libraries used, and sometimes fixed
[even before the end of the hackathon](https://gitlab.com/pgjones/quart/issues/72#note_63789221)

