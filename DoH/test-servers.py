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

def error(msg):
    print("ERROR: %s" % msg, file=sys.stderr)
    
def warning(msg):
    print("WARNING: %s" % msg, file=sys.stderr)

def info(msg):
    print("INFO: %s" % msg, file=sys.stderr)

class Storage:
    def __init__(self):
        self.contents = {}

    def store(self, buf):
        if buf.startswith(b"HTTP") or buf == b"\r\n":
            return
        (name, value) = buf.split(b":", maxsplit=1)
        self.contents[name] = value 

    def __str__(self):
        return self.contents

def setup(url, message, head=False, post=False):
    c = pycurl.Curl()
    if head and post:
        print("test_server cannot use HEAD and POST", file=sys.stderr)
        sys.exit(1)
    if head:
        c.setopt(pycurl.NOBODY, True)
    if post:
        c.setopt(c.URL, url)
        data = message.to_wire()
        c.setopt(pycurl.POST, True)
        c.setopt(pycurl.POSTFIELDS, data)
    else:
        c.setopt(c.URL, url + ("?ct&dns=%s" % base64.urlsafe_b64encode(message.to_wire()).decode('UTF8')))
    c.setopt(pycurl.HTTPHEADER, ["Content-type: application/dns-udpwireformat"])    
    # Does not work if pycurl was not compiled with nghttp2 (recent Debian
    # packages are OK) https://github.com/pycurl/pycurl/issues/477
    c.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2)
    return c

def test_server(url, message, head=False, post=False, wrong_ct=False, ask_impossible=False, insecure=False):
    c = setup(url, message, head, post)
    buffer = io.BytesIO()
    c.setopt(c.WRITEDATA, buffer)
    if wrong_ct:
            c.setopt(pycurl.HTTPHEADER, ["Content-type: text/plain"])
    if ask_impossible:
            c.setopt(pycurl.HTTPHEADER, ["Accept: application/postscript", "Content-type: application/dns-udpwireformat"]) 
    retrieved_headers = Storage()
    c.setopt(pycurl.HEADERFUNCTION, retrieved_headers.store)
    if insecure:
        c.setopt(pycurl.SSL_VERIFYPEER, False)   
        c.setopt(pycurl.SSL_VERIFYHOST, False)
    try:
        c.perform()
    except pycurl.error as py_error:
        if py_error.args[0] == 60: # Certificate error
            error("Invalid certificate: %s" % py_error.args[1])
            c.setopt(pycurl.SSL_VERIFYPEER, False)   
            c.setopt(pycurl.SSL_VERIFYHOST, False)
            buffer.getvalue() # Empty the buffer
            c.perform()
    rcode = c.getinfo(pycurl.RESPONSE_CODE)
    c.close()
    method = 'GET'
    if head:
        method = 'HEAD'
    elif post:
        method = 'POST'
    if rcode == 200:
        if not head:
            body = buffer.getvalue()
            response = dns.message.from_wire(body)
        if b"content-type" not in retrieved_headers.contents:
            error("No content type")
        if b"cache-control" not in retrieved_headers.contents:
            warning("No cache control")
        if wrong_ct:
            error("Wrong content type accepted")
        if ask_impossible:
            warning("Impossible content type requested and accepted")
    elif rcode == 405:
        if head:
            info("HEAD not implemented")
        elif post:
            info("POST not implemented")
        else:
            info("GET not implemented")
    elif rcode == 415:
        if not wrong_ct:
            error("Correct content type not accepted")
    else:
        error("HTTP error in reply to %s %i" % (method, rcode))
        
def usage(msg=None):
    if msg:
        print(msg,file=sys.stderr)
    print("Usage: %s domain-name url-server ..." % sys.argv[0], file=sys.stderr)

try:
    optlist, args = getopt.getopt (sys.argv[1:], "h",
                                   ["help"])
    for option, value in optlist:
        if option == "--help" or option == "-h":
            usage()
            sys.exit(0)
        else:
            error ("Unknown option " + option)
except getopt.error as reason:
    usage(reason)
    sys.exit(1)
if len(args) < 2:
    usage("Wrong number of arguments")
    sys.exit(1)
name = args[0]
message = dns.message.make_query(name, dns.rdatatype.ANY)
message.id = 0
for server in args[1:]:
    print(server)
    test_server(server, message)
    test_server(server, message, head=True, insecure=True)
    test_server(server, message, post=True, insecure=True)
    test_server(server, message, post=True, wrong_ct=True, insecure=True)
    test_server(server, message, post=True, ask_impossible=True, insecure=True)
    print("")
