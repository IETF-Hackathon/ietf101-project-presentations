#!/usr/bin/env python3

# http://pycurl.io/docs/latest
import pycurl

# http://www.dnspython.org/
import dns.message

import io
import sys
import base64
import getopt
import urllib.parse 

post = False
verbose = False
insecure = False
head = False

def usage(msg=None):
    if msg:
        print(msg,file=sys.stderr)
    print("Usage: %s [-P] [-k] url domain-name" % sys.argv[0], file=sys.stderr)

try:
    optlist, args = getopt.getopt (sys.argv[1:], "hvPke",
                                   ["help", "verbose", "head", "insecure", "POST"])
    for option, value in optlist:
        if option == "--help" or option == "-h":
            usage()
            sys.exit(0)
        elif option == "--verbose" or option == "-v":
            verbose = True
        elif option == "--head" or option == "-e":
            head = True
        elif option == "--insecure" or option == "-k":
            insecure = True
        elif option == "--POST" or option == "-P":
            post = True
        else:
            error ("Unknown option " + option)
except getopt.error as reason:
    usage(reason)
    sys.exit(1)
if post and head:
    usage("POST or HEAD but not both")
    sys.exit(1)
if len(args) != 2:
    usage("Wrong number of arguments")
    sys.exit(1)
url = args[0]
name = args[1]
buffer = io.BytesIO()
c = pycurl.Curl()
message = dns.message.make_query(name, dns.rdatatype.ANY)
message.id = 0 # DoH requests that
if head:
    c.setopt(pycurl.NOBODY, True)
if post:
    c.setopt(c.URL, url)
    data = message.to_wire()
    c.setopt(pycurl.POST, True)
    c.setopt(pycurl.POSTFIELDS, data)
else:
    dns_req = base64.urlsafe_b64encode(message.to_wire()).decode('UTF8').rstrip('=')
    c.setopt(c.URL, url + ("?ct&dns=%s" % dns_req))
c.setopt(pycurl.HTTPHEADER, ["Content-type: application/dns-udpwireformat"])
c.setopt(c.WRITEDATA, buffer)
if verbose:
    c.setopt(c.VERBOSE, True)
if insecure:
    c.setopt(pycurl.SSL_VERIFYPEER, False)   
    c.setopt(pycurl.SSL_VERIFYHOST, False)
# Does not work if pycurl was not compiled with nghttp2 (recent Debian
# packages are OK) https://github.com/pycurl/pycurl/issues/477
c.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2)
c.perform()
rcode = c.getinfo(pycurl.RESPONSE_CODE)
c.close()
if rcode == 200:
    if not head:
        body = buffer.getvalue()
        response = dns.message.from_wire(body)
        print(response)
    sys.exit(0)
else:
    body =  buffer.getvalue()
    if len(body) == 0:
        body = "[No details]"
    print("HTTP error %i: %s" % (rcode, body), file=sys.stderr)
    sys.exit(1)
