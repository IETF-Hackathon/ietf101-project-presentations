#!/usr/bin/env python3

# Defaults
bind = ''
resolver = "9.9.9.9"
port = 8081
verbose=False
check = False

# https://gitlab.com/pgjones/quart
from quart import Quart, request, Response, abort

# http//www.dnspython.org/
import dns.query

import ssl
import sys
import base64
import getopt

def error(msg):
    print("ERROR: %s" % msg, file=sys.stderr)
    
def warning(msg):
    print("WARNING: %s" % msg, file=sys.stderr)

def info(msg):
    print("INFO: %s" % msg, file=sys.stderr)

def usage(msg=None):
    if msg:
        print(msg,file=sys.stderr)
    print("Usage: %s [-c] [-r resolver] [-p listen-port]" % sys.argv[0], file=sys.stderr)

try:
    optlist, args = getopt.getopt (sys.argv[1:], "hvcr:p:b:",
                                   ["help", "verbose", "check", "bind=", "resolver=", "port="])
    for option, value in optlist:
        if option == "--help" or option == "-h":
            usage()
            sys.exit(0)
        elif option == "--verbose" or option == "-v":
            verbose = True
        elif option == "--check" or option == "-c":
            check = True
        elif option ==  "resolver" or option == "-r":
           resolver = value
        elif option ==  "bind" or option == "-b":
           bind = value
        elif option ==  "port" or option == "-p":
           port = value
        else:
            error ("Unknown option " + option)
except getopt.error as reason:
    usage(reason)
    sys.exit(1)
if len(args) != 0:
    usage("Wrong number of arguments")
    sys.exit(1)

app = Quart(__name__)

@app.route('/', methods=['HEAD', 'GET', 'POST'])
async def index():
   if request.method == 'POST':
      ct = request.headers.get('content-type')
      if ct != "application/dns-udpwireformat":
          abort(415)
      data = await request.get_data()
      r = bytes(data)
      info("Received %d bytes" % r)
   elif request.method == 'HEAD' or request.method == 'GET':
      form = request.args
      if check and "ct" not in form: # TODO an empty ct seems to be treated as missing?  https://gitlab.com/pgjones/quart/issues/72
         error("ct parameter is missing from the URI")
      # TODO test its value
      # TODO test the Accept:
      if "dns" not in form:
         if check:
            error("dns parameter is missing from the URI")
         return Response("dns parameter missing from the URI", status=400, mimetype='text/plain')
      padding = '=' * (-len(form['dns']) % 4)   
      r = base64.urlsafe_b64decode(form['dns'] + padding)
   else:
      abort(405)
   try:
         message = dns.message.from_wire(r)
         if check and message.id != 0:
             error("Query ID not null (%i)" % message.id)
   except:
         error("exception %s" % sys.exc_info()[0])
         return Response("Cannot parse your DNS request", status=400, mimetype='text/plain')
   return (dns.query.udp(message, resolver).to_wire(),
           {'Content-Type': 'application/dns-udpwireformat',
            'Cache-Control': 'no-cache'}) # TODO cache-control max-age
   # TODO handle timeouts and return SERVFAIL? Test with brk.internautique.fr

ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
ssl_context.set_ciphers('ECDHE+AESGCM')
ssl_context.load_cert_chain(certfile='le-cert.pem', keyfile='le-key.pem')
ssl_context.set_alpn_protocols(['h2', 'http/1.1'])
app.run(host=bind, port=port, ssl=ssl_context)
