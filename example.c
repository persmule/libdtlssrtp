#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "dtls_srtp.h"
#include "dsink_udp.h"


#define RTP_PACKET_LEN 8192

const char usage_format[] =
  "Usage: %s [options] [address] [port]\n"
  "Options:\n"
  "        -b:       address to bind\n"
  "        -c:       certificate file\n"
  "        -k:       private key file\n"
  "        -s        server mode\n"
  "        -p:       local port to bind\n";

const char optstr[] = "svb:c:k:h:p:";

const char cipherlist[] =
  "ECDHE-RSA-AES128-GCM-SHA256:"
  "ECDHE-ECDSA-AES128-GCM-SHA256:"
  "ECDHE-RSA-AES256-GCM-SHA384:"
  "ECDHE-ECDSA-AES256-GCM-SHA384:"
  "DHE-RSA-AES128-GCM-SHA256:"
  "kEDH+AESGCM:"
  "ECDHE-RSA-AES128-SHA256:"
  "ECDHE-ECDSA-AES128-SHA256:"
  "ECDHE-RSA-AES128-SHA:"
  "ECDHE-ECDSA-AES128-SHA:"
  "ECDHE-RSA-AES256-SHA384:"
  "ECDHE-ECDSA-AES256-SHA384:"
  "ECDHE-RSA-AES256-SHA:"
  "ECDHE-ECDSA-AES256-SHA:"
  "DHE-RSA-AES128-SHA256:"
  "DHE-RSA-AES128-SHA:"
  "DHE-RSA-AES256-SHA256:"
  "DHE-RSA-AES256-SHA:"
  "!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK";

const int on = 1, off = 0;

static int exitflag = 0;

static const struct timeval timeout = {5, 0};

static void setexit(int sig)
{
  if(sig == SIGINT){
    exitflag = 1;
  }
}

int fprinthex(FILE* fp, const char* prefix, const void* b, size_t l)
{
  int totallen = 0;
  const char* finger = (const char*)b;
  const char* end = finger + l;
  totallen += fprintf(fp, "%s:        %hhx", prefix, *(finger++));
  for(;finger != end; finger ++){
    totallen += fprintf(fp, ":%hhx", *finger);
  }
  totallen += fputs("\n\n", fp);
  return totallen;
}

int fprintkeymat(FILE* fp, const srtp_key_ptrs* ptrs)
{
  return fputs("********\n", fp)
    + fprinthex(fp, "localkey", ptrs->localkey, MASTER_KEY_LEN)
    + fprinthex(fp, "remotekey", ptrs->remotekey, MASTER_KEY_LEN)
    + fprinthex(fp, "localsalt", ptrs->localsalt, MASTER_SALT_LEN)
    + fprinthex(fp, "remotesalt", ptrs->remotesalt, MASTER_SALT_LEN)
    + fputs("********\n", fp);
}

int fprintfinger(FILE* fp, const char* prefix, const X509* cert)
{
  unsigned char fingerprint[EVP_MAX_MD_SIZE];
  unsigned int size = sizeof(fingerprint);
  memset(fingerprint, 0, sizeof(fingerprint));
  if(!X509_digest(cert, EVP_sha1(), fingerprint, &size)
     ||size == 0){
    fprintf(stderr, "Failed to generated fingerprint from X509 object %p\n", cert);
    return 0;
  }
  return fprinthex(fp, prefix, fingerprint, size);
}

int handle_socket_error(void) {
  switch (errno) {
  case EINTR:
    /* Interrupted system call.
     * Just ignore.
     */
    fprintf(stderr, "Interrupted system call!\n");
    return 1;
  case EBADF:
    /* Invalid socket.
     * Must close connection.
     */
    fprintf(stderr, "Invalid socket!\n");
    return 0;
    break;
#ifdef EHOSTDOWN
  case EHOSTDOWN:
    /* Host is down.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    fprintf(stderr, "Host is down!\n");
    return 1;
#endif
#ifdef ECONNRESET
  case ECONNRESET:
    /* Connection reset by peer.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    fprintf(stderr, "Connection reset by peer!\n");
    return 1;
#endif
  case ENOMEM:
    /* Out of memory.
     * Must close connection.
     */
    fprintf(stderr, "Out of memory!\n");
    return 0;
    break;
  case EACCES:
    /* Permission denied.
     * Just ignore, we might be blocked
     * by some firewall policy. Try again
     * and hope for the best.
     */
    fprintf(stderr, "Permission denied!\n");
    return 1;
    break;
  default:
    /* Something unexpected happened */
    fprintf(stderr, "Unexpected error! (errno = %d)\n", errno);
    return 0;
    break;
  }
  return 0;
}

typedef union usockaddr {
  struct sockaddr_storage ss;
  struct sockaddr_in6 s6;
  struct sockaddr_in s4;
}uaddr;

bool makesockaddr(const char* straddr, in_port_t port, uaddr* addr)
{
  if((straddr == NULL) || (strlen(straddr) == 0)){
      addr->s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
      addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
      addr->s6.sin6_addr = in6addr_any;
      addr->s6.sin6_port = htons(port);
  }else{
    if(1 == inet_pton(AF_INET, straddr, &addr->s4.sin_addr)){
      addr->s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
      addr->s4.sin_len = sizeof(struct sockaddr_in);
#endif
      addr->s4.sin_port = htons(port);
    }else if(1 == inet_pton(AF_INET6, straddr, &addr->s6.sin6_addr)){
	addr->s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
	addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	addr->s6.sin6_port = htons(port);
    }else{
      //straddr does contain a valid address.
      return false;
    }
  }
  return true;
}

socklen_t getsocklen(const uaddr* addr)
{
  if(addr == NULL){
    return 0;
  }
  switch(addr->ss.ss_family){
  case AF_INET:
    return sizeof(struct sockaddr_in);
  case AF_INET6:
    return sizeof(struct sockaddr_in6);
  default:
    return 0;
  }
}

fd_t prepare_udp_socket(const uaddr* addr)
{
  fd_t fd = socket(addr->ss.ss_family, SOCK_DGRAM, 0);
  if (fd < 0) {
    return fd;
  }

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#ifdef SO_REUSEPORT
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
  if (addr->ss.ss_family == AF_INET) {
    bind(fd, (const struct sockaddr *) addr, sizeof(struct sockaddr_in));
  } else {
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
    bind(fd, (const struct sockaddr *) addr, sizeof(struct sockaddr_in6));
  }
  return fd;
}

int mainloop(
	     fd_t fd,
	     SSL_CTX* cfg,
	     const struct timeval* timeout,
	     const int* toexit,
	     const uaddr* peer
	     )
{
  int ret = EXIT_FAILURE;
  //the side without a valid peer is considered the passive side.
  dtls_sess* dtls = dtls_sess_new(cfg, dsink_udp_getsink(), (peer == NULL));
  

  dtls_do_handshake(dtls, (void*)fd, (const void*)peer, getsocklen(peer));
  
  uint8_t payload[RTP_PACKET_LEN];
  while(*toexit == false){
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval l_timeout = *timeout;

    uaddr l_peer;
    if(peer != NULL){
      l_peer = *peer;
    }else{
      memset(&l_peer, 0, sizeof(l_peer));
    }
    socklen_t l_peerlen = sizeof(l_peer);
    int len = 0;
    
    int selected = select(fd + 1, &rfds, NULL, NULL, &l_timeout);
    if(selected == -1){
      perror("select()");
      break;
    }else if(selected > 0){
      //a packet is received.
      memset(payload, 0, sizeof(payload));
      len = recvfrom(fd, payload, sizeof(payload), 0, (struct sockaddr*)&l_peer, &l_peerlen);
      if(len < 0 && !handle_socket_error()){
	//packet received error!
	break;
      }
      if(packet_is_dtls(payload, len)){
	len = dtls_sess_put_packet(dtls, (void*)fd, payload, len, (const void*)&l_peer, l_peerlen);
	if((len < 0) && SSL_get_error(dtls->ssl, len) == SSL_ERROR_SSL){
	  fprintf(stderr, "DTLS failure occurred on dtls session %p due to reason '%s'\n", dtls, ERR_reason_error_string(ERR_get_error()));
	  break;
	}
	if(dtls->type == DTLS_CONTYPE_EXISTING){
	  //SSL_is_init_finished(), print key material.
	  {
	    X509 *peercert = dtls_sess_get_pear_certificate(dtls);
	    if(peercert == NULL){
	      fprintf(stderr, "No certificate was provided by the peer on dtls session %p\n", dtls);
	      break;
	    }
	    fprintfinger(stdout, "Fingerprint of peer's cert is ", peercert);
	    X509_free(peercert);
	  }
	  srtp_key_material* km = srtp_get_key_material(dtls);
	  if(km == NULL){
	    fprintf(stderr, "Unable to extract SRTP keying material from dtls session %p\n", dtls);
	    break;
	  }
	  srtp_key_ptrs ptrs = {0, 0, 0, 0};
	  srtp_key_material_extract(km, &ptrs);
	  fprintkeymat(stdout, &ptrs);
	  key_material_free(km);
	  if(peer == NULL){
	    //demo works as server.
	    dtls_sess_setup(dtls);
	    continue;
	  }else{
	    ret = EXIT_SUCCESS;
	    break;
	  }
	}
      }else{
	//in real rtp program, parse rtp packets here.
	continue;
      }
    }else{
      //no packet arrived, selected() returns for timeout.
      continue;
    }
  }
  dtls_sess_free(dtls);
  return ret;
}

int main(int argc, char** argv)
{
  if(!dtls_init_openssl()){
    fputs("Openssl initialization failed! quitting.\n", stderr);
    return EXIT_FAILURE;
  }
  int ret = EXIT_FAILURE;
  if(argc <= 1){
    fprintf(stderr, usage_format, argv[0]);
    return EXIT_FAILURE;
  }
  const char *bindaddr = NULL,
    *peeraddr = NULL,
    *certfile = NULL,
    *pkeyfile = NULL;

  bool server = false;

  in_port_t port = 0, lport = 0;
  {
    int opt = getopt(argc, argv, optstr);
    for(; opt != -1; opt = getopt(argc, argv, optstr)){
      switch(opt){
      case 'b':
	bindaddr = optarg;
	break;
      case 'c':
	certfile = optarg;
	break;
      case 'k':
	pkeyfile = optarg;
	break;
      case 's':
	server = true;
	break;
      case 'p':
	lport = atoi(optarg);
	break;
      default:
	fprintf(stderr, usage_format, argv[0]);
	return EXIT_FAILURE;
      }
    }
  }
  
  do{
    peeraddr = argv[optind];
    if(argv[optind + 1] != NULL){
      port = atoi(argv[optind + 1]);
    }
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = setexit;
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);
    
    
    tlscfg cfg = {0, 0, SRTP_PROFILE_AES128_CM_SHA1_80, cipherlist, 0, 0};
    SSL_CTX* sslcfg = NULL;
    do{
      if(certfile == NULL || pkeyfile == NULL){
	fputs("No keyfiles provided!\n", stderr);
	break;
      }
      BIO* fb = BIO_new_file(certfile, "rb");
      if(NULL == (cfg.cert = PEM_read_bio_X509(fb, NULL, NULL, NULL))){
	fputs("Fail to parse certificate file!\n", stderr);
	BIO_free(fb);
	break;
      }
      fprintfinger(stdout, "Fingerprint of local cert is ", cfg.cert);
      BIO_free(fb);
      fb = BIO_new_file(pkeyfile, "rb");
      if(NULL == (cfg.pkey = PEM_read_bio_PrivateKey(fb, NULL, NULL, NULL))){
	fputs("Fail to parse private key file!\n", stderr);
	BIO_free(fb);
	break;
      }
      BIO_free(fb);
      sslcfg = dtls_ctx_init(DTLS_VERIFY_FINGERPRINT, NULL, &cfg);
      if(sslcfg == NULL){
	fputs("Fail to generate SSL_CTX!\n", stderr);
	break;
      }
      uaddr laddr, raddr;
      if(!makesockaddr(bindaddr, lport, &laddr)){
	fputs("Local address is invalid!\n", stderr);
	break;
      }
      if(!server){
	if((peeraddr == NULL) || (port == 0)){
	  fputs("No peer address and/or port while in client mode!\n", stderr);
	  break;
	}
	if(!makesockaddr(peeraddr, port, &raddr)){
	  fputs("remote address is invalid!\n", stderr);
	  break;
	}
      }
      fd_t fd = prepare_udp_socket(&laddr);
      do{
	ret = mainloop(fd, sslcfg, &timeout, &exitflag, server?NULL:&raddr);
      }while(0);
      close(fd);
    }while(0);
    
    if(sslcfg)SSL_CTX_free(sslcfg);
    if(cfg.cert)X509_free(cfg.cert);
    if(cfg.pkey)EVP_PKEY_free(cfg.pkey);
    
  }while(0);
  dtls_uninit_openssl();
  return ret;
}
