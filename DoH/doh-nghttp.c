#include <signal.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

/* libevent.org */
#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>

#include <nghttp2/nghttp2.h>

/* libhttp-parser-dev */
#include <http_parser.h>

/* getdns */
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <gldns/parseutil.h>

#define errx(exitcode, format, args...)                                        \
  {                                                                            \
    warnx(format, ##args);                                                     \
    exit(exitcode);                                                            \
  }
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)

#define MAXURILENGTH 512
#define MAXHOSTLENGTH 256

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

static int verbose_flag, post_flag = 0;

static void
print_header (FILE * f, const uint8_t * name, size_t namelen,
	      const uint8_t * value, size_t valuelen)
{
  fwrite (name, 1, namelen, f);
  fprintf (f, ": ");
  fwrite (value, 1, valuelen, f);
  fprintf (f, "\n");
}

static void
print_headers (FILE * f, nghttp2_nv * nva, size_t nvlen)
{
  size_t i;
  for (i = 0; i < nvlen; ++i)
    {
      print_header (f, nva[i].name, nva[i].namelen, nva[i].value,
		    nva[i].valuelen);
    }
  fprintf (f, "\n");
}

static int
select_next_proto_cb (SSL * ssl, unsigned char **out,
		      unsigned char *outlen, const unsigned char *in,
		      unsigned int inlen, void *arg)
{
  (void) ssl;
  (void) arg;

  if (nghttp2_select_next_protocol (out, outlen, in, inlen) <= 0)
    {
      errx (1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
    }
  return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *
create_ssl_ctx (void)
{
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new (SSLv23_client_method ());
  if (!ssl_ctx)
    {
      errx (1, "Could not create SSL/TLS context: %s",
	    ERR_error_string (ERR_get_error (), NULL));
    }
  SSL_CTX_set_options (ssl_ctx,
		       SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		       SSL_OP_NO_COMPRESSION |
		       SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  SSL_CTX_set_next_proto_select_cb (ssl_ctx, select_next_proto_cb, NULL);

  SSL_CTX_set_alpn_protos (ssl_ctx, (const unsigned char *) "\x02h2", 3);
  return ssl_ctx;
}

static SSL *
create_ssl (SSL_CTX * ssl_ctx)
{
  SSL *ssl;
  ssl = SSL_new (ssl_ctx);
  if (!ssl)
    {
      errx (1, "Could not create SSL/TLS session object: %s",
	    ERR_error_string (ERR_get_error (), NULL));
    }
  return ssl;
}

typedef struct
{
  /* The NULL-terminated URI string to retrieve. */
  const char *uri;
  /* Parsed result of the |uri| */
  struct http_parser_url *u;
  /* The authority portion of the |uri|, not NULL-terminated */
  char *authority;
  /* The path portion of the |uri|, including query, not NULL-terminated */
  char *path;
  /* The length of the |authority| */
  size_t authoritylen;
  /* The length of the |path| */
  size_t pathlen;
  /* The stream ID of this stream */
  int32_t stream_id;
} http2_stream_data;

typedef struct
{
  nghttp2_session *session;
  struct evdns_base *dnsbase;
  struct bufferevent *bev;
  http2_stream_data *stream_data;
  char *qname;
  uint8_t **request_wr;
  unsigned int request_wr_length;
  unsigned short int post;
  nghttp2_data_provider *provider;
} http2_session_data;


/* Send HTTP request to the remote peer */
static void
submit_request (http2_session_data * session_data)
{
  int32_t stream_id;
  http2_stream_data *stream_data = session_data->stream_data;
  const char *uri = stream_data->uri;
  const struct http_parser_url *u = stream_data->u;
  char *npath = malloc (1024);
  getdns_return_t result;
  uint8_t **buffer;
  int b;
  size_t size;
  const char *ctype = "application/dns-udpwireformat";
  getdns_dict *qdict;
  char qdict_str[1124];
  char *b64s;
  char *method;
  buffer = malloc (1024);
  b64s = malloc (1024);
  npath[0] = '\0';
  strncpy (npath, stream_data->path, stream_data->pathlen);
  npath[stream_data->pathlen] = '\0';
  (void) snprintf( qdict_str, sizeof(qdict_str)
                 , "{header:{rd:1},question:{qtype:GETDNS_RRTYPE_A,qname:%s.}}"
                 , session_data->qname);
  result = getdns_str2dict(qdict_str, &qdict);
  if (result != GETDNS_RETURN_GOOD)
    {
      fprintf (stderr, "Cannot set dict qdict: %s\n",
	       getdns_get_errorstr_by_id (result));
      exit (1);
    }
  if (verbose_flag)
    {
      fprintf (stderr, "%s\n", getdns_pretty_print_dict (qdict));
    }
  if (session_data->post)
    {
      method = "POST";
    }
  else
    {
      method = "GET";
    }
  result = getdns_msg_dict2wire (qdict, buffer, &size);
  if (result != GETDNS_RETURN_GOOD)
    {
      fprintf (stderr, "Cannot convert to wire: %s\n",
	       getdns_get_errorstr_by_id (result));
      exit (1);
    }
  memcpy (session_data->request_wr, buffer, size);
  session_data->request_wr_length = size;
  fprintf (stderr, "DEBUG Produced a DNS message of %d bytes\n", (int) size);
  /* fprintf(stderr, "Send %d bytes: %s\n", b, b64s); */
  if (!post_flag)
    {
      b = gldns_b64_ntop (*buffer, size, b64s, 1024);
      strcat (npath, "?ct&dns=");
      strcat (npath, b64s);
    }
  char *size_str;
  size_str = malloc (1024);
  sprintf (size_str, "%d", size);
  nghttp2_nv hdrs[6] = {
    MAKE_NV (":method", method, strlen (method)),
    MAKE_NV (":scheme", &uri[u->field_data[UF_SCHEMA].off],
	     u->field_data[UF_SCHEMA].len),
    MAKE_NV (":authority", stream_data->authority, stream_data->authoritylen),
    MAKE_NV (":path", npath, strlen (npath)),
    MAKE_NV (":content-type", ctype, strlen (ctype)),
    MAKE_NV (":content-length", size_str, strlen (size_str))
  };;
  unsigned short int hdrs_offset;
  if (post_flag)
    {
      hdrs_offset = 0;
    }
  else
    {
      hdrs_offset = 2;
    }
  if (verbose_flag)
    {
      fprintf (stderr, "Request headers:\n");
      print_headers (stderr, hdrs, ARRLEN (hdrs) - hdrs_offset);
    }
  stream_id = nghttp2_submit_request (session_data->session, NULL, hdrs,
				      ARRLEN (hdrs) - hdrs_offset,
				      session_data->provider, stream_data);
  if (stream_id < 0)
    {
      errx (1, "Could not submit HTTP request: %s",
	    nghttp2_strerror (stream_id));
    }

  stream_data->stream_id = stream_id;
}

static ssize_t
send_callback (nghttp2_session * session, const uint8_t * data,
	       size_t length, int flags, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *) user_data;
  struct bufferevent *bev = session_data->bev;
  (void) session;
  (void) flags;

  bufferevent_write (bev, data, length);
  return (ssize_t) length;
}

static int
on_header_callback (nghttp2_session * session,
		    const nghttp2_frame * frame, const uint8_t * name,
		    size_t namelen, const uint8_t * value,
		    size_t valuelen, uint8_t flags, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *) user_data;
  (void) session;
  (void) flags;

  switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
	  session_data->stream_data->stream_id == frame->hd.stream_id)
	{
	  /* Print response headers for the initiated request. */
	  if (verbose_flag)
	    {
	      print_header (stderr, name, namelen, value, valuelen);
	    }
	  break;
	}
    }
  return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
static int
on_begin_headers_callback (nghttp2_session * session,
			   const nghttp2_frame * frame, void *user_data)
{
  char host[MAXHOSTLENGTH];
  http2_session_data *session_data = (http2_session_data *) user_data;
  (void) session;
  strncpy (host, session_data->stream_data->authority,
	   session_data->stream_data->authoritylen);
  host[session_data->stream_data->authoritylen] = '\0';
  switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
	  session_data->stream_data->stream_id == frame->hd.stream_id)
	{
	  if (verbose_flag)
	    {
	      fprintf (stderr,
		       "Response headers for stream ID=%d for host %s:\n",
		       frame->hd.stream_id, host);
	    }
	}
      break;
    }
  return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int
on_frame_recv_callback (nghttp2_session * session,
			const nghttp2_frame * frame, void *user_data)
{
  char host[MAXHOSTLENGTH];
  http2_session_data *session_data = (http2_session_data *) user_data;
  (void) session;
  strncpy (host, session_data->stream_data->authority,
	   session_data->stream_data->authoritylen);
  host[session_data->stream_data->authoritylen] = '\0';

  switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
	  session_data->stream_data->stream_id == frame->hd.stream_id)
	{
	  if (verbose_flag)
	    {
	      fprintf (stderr, "All headers received for host %s\n\n", host);
	    }
	}
      break;
    }
  return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
   received from the remote peer. In this implementation, if the frame
   is meant to the stream we initiated, print the received data in
   stdout, so that the user can redirect its output to the file
   easily. */
static int
on_data_chunk_recv_callback (nghttp2_session * session, uint8_t flags,
			     int32_t stream_id, const uint8_t * data,
			     size_t len, void *user_data)
{
  char host[MAXHOSTLENGTH];
  getdns_return_t this_ret;
  uint32_t this_error;
  http2_session_data *session_data = (http2_session_data *) user_data;
  getdns_dict *msg_dict;
  (void) session;
  (void) flags;
  getdns_wire2msg_dict (data, len, &msg_dict);
  if (session_data->stream_data->stream_id == stream_id)
    {
      this_ret = getdns_dict_get_int (msg_dict, "/header/rcode", &this_error);
      if (this_error != GETDNS_RCODE_NOERROR)	// If the search didn't return
	// "good"
	{
	  fprintf (stderr,
		   "The search had no results, and a return value of %d. Exiting.\n",
		   this_error);
	  exit (0);
	}
      if (verbose_flag)
	{
	  fprintf (stderr, "%s\n", getdns_pretty_print_dict (msg_dict));
	}
      getdns_bindata *this_address_data;
      this_ret =
	getdns_dict_get_bindata (msg_dict,
				 "/answer/0/rdata/ipv4_address",
				 &this_address_data);
      if (this_ret != GETDNS_RETURN_GOOD)	// This check is really not needed,
	// but
	// prevents a compiler error under
	// "pedantic"
	{
	  fprintf (stderr, "Trying to get the answers failed: %s\n",
		   getdns_get_errorstr_by_id (this_ret));
	  return 0;
	}
      char *this_address_str = getdns_display_ip_address (this_address_data);
      fprintf (stdout, "The address is %s\n", this_address_str);
      free (this_address_str);

      return 0;
    }
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
static int
on_stream_close_callback (nghttp2_session * session, int32_t stream_id,
			  uint32_t error_code, void *user_data)
{
  char host[MAXHOSTLENGTH];
  http2_session_data *session_data = (http2_session_data *) user_data;
  int rv;

  strncpy (host, session_data->stream_data->authority,
	   session_data->stream_data->authoritylen);
  host[session_data->stream_data->authoritylen] = '\0';
  if (session_data->stream_data->stream_id == stream_id)
    {
      if (verbose_flag)
	{
	  fprintf (stderr,
		   "Stream %d (host %s) closed with error_code=%u\n\n",
		   stream_id, host, error_code);
	}
      rv = nghttp2_session_terminate_session (session, NGHTTP2_NO_ERROR);
      if (rv != 0)
	{
	  return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
    }
  return 0;
}


static ssize_t
post_data_read_callback (nghttp2_session * session, int32_t stream_id,
			 uint8_t * buf, size_t length, uint32_t * data_flags,
			 nghttp2_data_source * source, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *) user_data;
  fprintf (stderr, "DEBUG: %s (%d bytes / %d) on stream %d\n",
	   session_data->qname, session_data->request_wr_length, length,
	   stream_id);
  memcpy (buf, session_data->request_wr, session_data->request_wr_length);
  *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  return (ssize_t) session_data->request_wr_length;
}

static void
initialize_nghttp2_session (http2_session_data * session_data)
{
  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new (&callbacks);

  nghttp2_session_callbacks_set_send_callback (callbacks, send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback (callbacks,
							on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback (callbacks,
							     on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback (callbacks,
							  on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback (callbacks,
						    on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback (callbacks,
							   on_begin_headers_callback);

  nghttp2_session_client_new (&session_data->session, callbacks,
			      session_data);

  nghttp2_session_callbacks_del (callbacks);
}

static void
send_client_connection_header (http2_session_data * session_data)
{
  nghttp2_settings_entry iv[1] = {
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
  };
  int rv;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings (session_data->session, NGHTTP2_FLAG_NONE, iv,
				ARRLEN (iv));
  if (rv != 0)
    {
      errx (1, "Could not submit SETTINGS: %s", nghttp2_strerror (rv));
    }
}

static http2_stream_data *
create_http2_stream_data (const char *uri, struct http_parser_url *u)
{
  /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
  size_t extra = 7;
  http2_stream_data *stream_data = malloc (sizeof (http2_stream_data));

  stream_data->uri = uri;
  stream_data->u = u;
  stream_data->stream_id = -1;

  stream_data->authoritylen = u->field_data[UF_HOST].len;
  stream_data->authority = malloc (stream_data->authoritylen + extra);
  memcpy (stream_data->authority, &uri[u->field_data[UF_HOST].off],
	  u->field_data[UF_HOST].len);
  if (u->field_set & (1 << UF_PORT))
    {
      stream_data->authoritylen +=
	(size_t) snprintf (stream_data->authority +
			   u->field_data[UF_HOST].len, extra, ":%u", u->port);
    }

  /* If we don't have path in URI, we use "/" as path. */
  stream_data->pathlen = 1;
  if (u->field_set & (1 << UF_PATH))
    {
      stream_data->pathlen = u->field_data[UF_PATH].len;
    }
  if (u->field_set & (1 << UF_QUERY))
    {
      /* +1 for '?' character */
      stream_data->pathlen += (size_t) (u->field_data[UF_QUERY].len + 1);
    }

  stream_data->path = malloc (stream_data->pathlen);
  if (u->field_set & (1 << UF_PATH))
    {
      memcpy (stream_data->path, &uri[u->field_data[UF_PATH].off],
	      u->field_data[UF_PATH].len);
    }
  else
    {
      stream_data->path[0] = '/';
    }
  if (u->field_set & (1 << UF_QUERY))
    {
      stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len -
			1] = '?';
      memcpy (stream_data->path + stream_data->pathlen -
	      u->field_data[UF_QUERY].len, &uri[u->field_data[UF_QUERY].off],
	      u->field_data[UF_QUERY].len);
    }

  return stream_data;
}

static void
delete_http2_stream_data (http2_stream_data * stream_data)
{
  free (stream_data->path);
  free (stream_data->authority);
  free (stream_data);
}

/* Initializes |session_data| */
static http2_session_data *
create_http2_session_data (struct event_base *evbase)
{
  http2_session_data *session_data = malloc (sizeof (http2_session_data));

  memset (session_data, 0, sizeof (http2_session_data));
  session_data->dnsbase = evdns_base_new (evbase, 1);
  session_data->request_wr = malloc (1024);
  session_data->request_wr_length = 0;
  session_data->provider = NULL;
  session_data->post = 0;
  return session_data;
}

static void
delete_http2_session_data (http2_session_data * session_data)
{
  SSL *ssl = bufferevent_openssl_get_ssl (session_data->bev);

  if (ssl)
    {
      SSL_shutdown (ssl);
    }
  bufferevent_free (session_data->bev);
  session_data->bev = NULL;
  evdns_base_free (session_data->dnsbase, 1);
  session_data->dnsbase = NULL;
  nghttp2_session_del (session_data->session);
  session_data->session = NULL;
  if (session_data->stream_data)
    {
      delete_http2_stream_data (session_data->stream_data);
      session_data->stream_data = NULL;
    }
  free (session_data);
}

static int
session_send (http2_session_data * session_data)
{
  int rv;

  rv = nghttp2_session_send (session_data->session);
  if (rv != 0)
    {
      warnx ("Fatal error: %s", nghttp2_strerror (rv));
      return -1;
    }
  return 0;
}

static void
readcb (struct bufferevent *bev, void *ptr)
{
  http2_session_data *session_data = (http2_session_data *) ptr;
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input (bev);
  size_t datalen = evbuffer_get_length (input);
  unsigned char *data = evbuffer_pullup (input, -1);

  readlen = nghttp2_session_mem_recv (session_data->session, data, datalen);
  if (readlen < 0)
    {
      warnx ("Fatal error: %s", nghttp2_strerror ((int) readlen));
      delete_http2_session_data (session_data);
      return;
    }
  if (evbuffer_drain (input, (size_t) readlen) != 0)
    {
      warnx ("Fatal error: evbuffer_drain failed");
      delete_http2_session_data (session_data);
      return;
    }
  if (session_send (session_data) != 0)
    {
      delete_http2_session_data (session_data);
      return;
    }
}

static void
writecb (struct bufferevent *bev, void *ptr)
{
  http2_session_data *session_data = (http2_session_data *) ptr;
  (void) bev;

  if (nghttp2_session_want_read (session_data->session) == 0 &&
      nghttp2_session_want_write (session_data->session) == 0 &&
      evbuffer_get_length (bufferevent_get_output (session_data->bev)) == 0)
    {
      delete_http2_session_data (session_data);
    }
}

static void
eventcb (struct bufferevent *bev, short events, void *ptr)
{
  http2_session_data *session_data = (http2_session_data *) ptr;
  if (events & BEV_EVENT_CONNECTED)
    {
      int fd = bufferevent_getfd (bev);
      int val = 1;
      const unsigned char *alpn = NULL;
      unsigned int alpnlen = 0;
      SSL *ssl;
      char host[MAXHOSTLENGTH];
      strncpy (host, session_data->stream_data->authority,
	       session_data->stream_data->authoritylen);
      host[session_data->stream_data->authoritylen] = '\0';
      if (verbose_flag)
	{
	  fprintf (stderr, "Connected to %s\n", host);
	}
      ssl = bufferevent_openssl_get_ssl (session_data->bev);

      SSL_get0_next_proto_negotiated (ssl, &alpn, &alpnlen);
      if (alpn == NULL)
	{
	  SSL_get0_alpn_selected (ssl, &alpn, &alpnlen);
	}

      if (alpn == NULL || alpnlen != 2 || memcmp ("h2", alpn, 2) != 0)
	{
	  fprintf (stderr, "h2 is not negotiated for %s\n", host);
	  delete_http2_session_data (session_data);
	  return;
	}

      setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof (val));
      initialize_nghttp2_session (session_data);
      send_client_connection_header (session_data);
      submit_request (session_data);
      if (session_send (session_data) != 0)
	{
	  delete_http2_session_data (session_data);
	}
      return;
    }
  if (events & BEV_EVENT_EOF)
    {
      warnx ("Disconnected from the remote host");
    }
  else if (events & BEV_EVENT_ERROR)
    {
      warnx ("Network error");
    }
  else if (events & BEV_EVENT_TIMEOUT)
    {
      warnx ("Timeout");
    }
  delete_http2_session_data (session_data);
}

static void
initiate_connection (struct event_base *evbase, SSL_CTX * ssl_ctx,
		     const char *host, uint16_t port,
		     http2_session_data * session_data)
{
  int rv;
  struct bufferevent *bev;
  SSL *ssl;

  ssl = create_ssl (ssl_ctx);
  bev =
    bufferevent_openssl_socket_new (evbase, -1, ssl,
				    BUFFEREVENT_SSL_CONNECTING,
				    BEV_OPT_DEFER_CALLBACKS |
				    BEV_OPT_CLOSE_ON_FREE);
  bufferevent_enable (bev, EV_READ | EV_WRITE);
  bufferevent_setcb (bev, readcb, writecb, eventcb, session_data);
  rv = bufferevent_socket_connect_hostname (bev, session_data->dnsbase,
					    AF_UNSPEC, host, port);

  if (rv != 0)
    {
      errx (1, "Could not connect to the remote host %s", host);
    }
  session_data->bev = bev;
}

int
main (int argc, char **argv)
{

  char c;
  static struct option long_options[] = {
    {"verbose", no_argument, &verbose_flag, 0},
    {"post", no_argument, &post_flag, 0},
    {0, 0, 0, 0}
  };

  struct sigaction act;
  char *uri;
  struct http_parser_url u;
  char *host;
  uint16_t port;
  int rv;
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
  http2_session_data *session_data;

  while (1)
    {
      /* getopt_long stores the option index here.  */
      int option_index = 0;

      c = getopt_long (argc, argv, "hvp", long_options, &option_index);

      /* Detect the end of the options.  */
      if (c == -1)
	break;
      switch (c)
	{
	case 0:
	  /* If this option set a flag, do nothing else now.  */
	  if (long_options[option_index].flag != 0)
	    break;
	  printf ("option %s", long_options[option_index].name);
	  if (optarg)
	    printf (" with arg %s", optarg);
	  printf ("\n");
	  if (strcmp (long_options[option_index].name, "message") == 0)
	    {
	      /* message = optarg; */
	    }
	  else
	    {
	      printf ("Internal error: unknown option %s\n",
		      long_options[option_index].name);
	      abort ();
	    }
	  break;
	case 'v':
	  verbose_flag = 1;
	  break;
	case 'p':
	  post_flag = 1;
	  break;
	case '?':
	  /* getopt_long already printed an error message.  */
	  break;
	default:
	  printf ("Internal error: unknown option %c\n", c);
	  abort ();
	}
    }

  /* Check args */
  if (argc - optind < 2)
    {
      fprintf (stderr, "Usage: %s [-v] [-p] http_uri domain_name\n", argv[0]);
      exit (EXIT_FAILURE);
    }

  if (post_flag)
    {
      warnx ("POST does not currently work (TODO)");
    }
  /* Initialize */
  memset (&act, 0, sizeof (struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction (SIGPIPE, &act, NULL);
  SSL_load_error_strings ();
  SSL_library_init ();
  ssl_ctx = create_ssl_ctx ();
  evbase = event_base_new ();

  /* Parse URI */
  uri = malloc (MAXURILENGTH);
  strncpy (uri, argv[optind], strlen (argv[optind]));
  uri[strlen (argv[optind])] = '\0';
  if (verbose_flag)
    {
      fprintf (stderr, "Asking %s...\n\n", uri);
    }
  rv = http_parser_parse_url (uri, strlen (uri), 0, &u);
  if (rv != 0)
    {
      errx (1, "Could not parse URI %s", uri);
    }
  host = strndup (&uri[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
  if (!(u.field_set & (1 << UF_PORT)))
    {
      port = 443;
    }
  else
    {
      port = u.port;
    }

  /* Communicate */
  session_data = create_http2_session_data (evbase);
  session_data->stream_data = create_http2_stream_data (uri, &u);
  session_data->qname = argv[optind + 1];
  if (post_flag)
    {
      session_data->post = 1;
      session_data->provider = malloc (sizeof (nghttp2_data_provider));
      /* Data does not come from outside, no need for a file descriptor */
      session_data->provider->source.fd = 0;
      session_data->provider->source.ptr = session_data->request_wr;
      session_data->provider->read_callback = post_data_read_callback;
    }
  else
    {
      session_data->post = 0;
    }
  initiate_connection (evbase, ssl_ctx, host, port, session_data);

  /* Clean */
  free (host);
  host = NULL;

  event_base_loop (evbase, 0);
  event_base_free (evbase);
  SSL_CTX_free (ssl_ctx);
  return 0;
}
