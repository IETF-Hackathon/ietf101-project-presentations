# Code written for the DoH ([DNS-over-HTTPS](https://datatracker.ietf.org/wg/doh)) work.

## Servers

TODO

[Tony Finch's proxy](https://fanf.dreamwidth.org/123507.html)

## Clients

[JavaScript code ](https://github.com/pusateri/doh-client)

TODO

## Libraries

Work is under way for the C library [getdns](https://getdnsapi.net)

Work is under way for
[Go DNS](https://miek.nl/2014/august/16/go-dns-package/) [The plan](https://miek.nl/2018/february/19/ietf-101-dns-hackathon/)

## Public DoH servers

* https://dns.dnsoverhttps.net/dns-query 
* https://dns.google.com/experimental
* https://dns.cloudflare.com/.well-known/dns-query
* https://dns.bortzmeyer.fr (ephemeral / temporary)
* https://vm1.dev.dns.cam.ac.uk/doh (v6 only, ephemeral / temporary)

## Ideas for interoperability testing

Client side tests are tests that would be run from the client to test the server conformance

Server side tests are errors that would be logged if a client was to send invalid content

## Client side

* correct MIME type
* return code should be 415 when the content type is invalid
* return code should be 405 when the method is not accepted (check that Allow header is set). What about HEAD? if the server does not accept GET, then HEAD is pointless . doh-proxy fail the HEAD handling: https://github.com/facebookexperimental/doh-proxy/issues/37
* return code should be 406 when the content type is not accepted by the server: does the server returns a list of accepted content type?
* does server supports GET
* does server supports POST
* Invalid certificates should be rejected
* "intelligent" use of the cache-control and expires headers
* send Base64 with padding

## Server Side

* ID set to 0
* if GET, check that ct= and dns= exist and that ct= has a proper value
* check the MIME type

