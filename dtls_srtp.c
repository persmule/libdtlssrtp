#include "dtls_srtp.h"



SSL_VERIFY_CB(dtls_trivial_verify_callback)
{
  //TODO: add actuall verify routines here, if needed.
  (void)preverify_ok;
  (void)ctx;
  return 1;
}

int check_socket(fd_t socket)
{
  int socktype = 0;
  socklen_t optlen = sizeof(socktype);
  if(0 != getsockopt(socket, SOL_SOCKET, SO_TYPE, &socktype, &optlen)){
    switch(errno){
      //TODO: add more accurate error-parsing process.
    default:
      return false;
    }
  }
  if(socktype != SOCK_DGRAM){
    //socket is not for udp.
    return false;
  }
  return true;
}

SSL_CTX* dtls_ctx_init(
		       int verify_mode,
		       ssl_verify_cb* cb,
		       const tlscfg* cfg
		       )
{
  SSL_CTX* ctx = NULL;
#ifndef HAVE_OPENSSL_ECDH_AUTO
  EC_KEY *ecdh = NULL;
#endif
  
  ctx = SSL_CTX_new(DTLSv1_method());
  
  SSL_CTX_set_read_ahead(ctx, true);
#ifdef HAVE_OPENSSL_ECDH_AUTO
  SSL_CTX_set_ecdh_auto(ctx, true);
#else
  if (NULL != (ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
  }
#endif
  SSL_CTX_set_verify(ctx,
		     (verify_mode & DTLS_VERIFY_FINGERPRINT)
		     || (verify_mode & DTLS_VERIFY_CERTIFICATE) ?
		     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		     : SSL_VERIFY_NONE,
		     !(verify_mode & DTLS_VERIFY_CERTIFICATE) ?
		     (cb ? cb:dtls_trivial_verify_callback) : NULL
		     );

  switch(cfg->profile) {
  case SRTP_PROFILE_AES128_CM_SHA1_80:
    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
    break;
  case SRTP_PROFILE_AES128_CM_SHA1_32:
    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_32");
    break;
  default:
    SSL_CTX_free(ctx);
    return NULL;
  }
  
  if(cfg->cert != NULL) {
    if (!SSL_CTX_use_certificate(ctx, cfg->cert)) {
      SSL_CTX_free(ctx);
      return NULL;
    }
    
    if (!SSL_CTX_use_PrivateKey(ctx, cfg->pkey) ||
	!SSL_CTX_check_private_key(ctx)) {
      SSL_CTX_free(ctx);
      return NULL;
    }
  }
  
  if (!str_isempty(cfg->cipherlist)) {
    if (!SSL_CTX_set_cipher_list(ctx, cfg->cipherlist)) {
      SSL_CTX_free(ctx);
      return NULL;
    }
  }
  
  if (!str_isempty(cfg->cafile) || !str_isempty(cfg->capath)) {
    if (!SSL_CTX_load_verify_locations(ctx, str_nullforempty(cfg->cafile), str_nullforempty(cfg->capath))) {
      SSL_CTX_free(ctx);
      return NULL;
    }
  }
  
  return ctx;
}

dtls_sess* dtls_sess_new(SSL_CTX* sslcfg, bool is_passive)
{
  dtls_sess* sess = (dtls_sess*)calloc(1, sizeof(dtls_sess));
  BIO* rbio = NULL;
  BIO* wbio = NULL;

  sess->state = is_passive;
  
  if (NULL == (sess->ssl = SSL_new(sslcfg))) {
    goto error;
  }

  if (NULL == (rbio = BIO_new(BIO_s_mem()))) {
    goto error;
  }

  BIO_set_mem_eof_return(rbio, -1);

  if (NULL == (wbio = BIO_new(BIO_s_mem()))) {
    BIO_free(rbio);
    rbio = NULL;
    goto error;
  }

  BIO_set_mem_eof_return(wbio, -1);

  SSL_set_bio(sess->ssl, rbio, wbio);
  
  BIO_free(rbio);
  BIO_free(wbio);

  dtls_sess_setup(sess);

  return sess;
  
 error:
  if(sess->ssl != NULL) {
    SSL_free(sess->ssl);
    sess->ssl = NULL;
  }
  free(sess);
  return NULL;
}

void dtls_sess_free(dtls_sess* sess)
{
  if(sess->ssl != NULL) {
    SSL_free(sess->ssl);
    sess->ssl = NULL;
  }
  pthread_mutex_destroy(&sess->lock);
  free(sess);
}

ptrdiff_t dtls_sess_send_pending(
				 dtls_sess* sess,
				 fd_t fd,
				 const struct sockaddr *dest_addr,
				 socklen_t addrlen
				 )
{
  if(sess->ssl == NULL){
    return -1;
  }
  BIO* wbio = dtls_sess_get_wbio(sess);
  size_t pending = BIO_ctrl_pending(wbio);
  size_t out = 0;
  ptrdiff_t ret = 0;
  if(pending > 0) {
    char outgoing[pending];
    out = BIO_read(wbio, outgoing, pending);
    ret = sendto(fd, outgoing, out, 0, dest_addr, addrlen);
  }
  return ret;
}

ptrdiff_t dtls_sess_put_packet(
			       dtls_sess* sess,
			       fd_t fd,
			       const void* buf,
			       size_t len,
			       const struct sockaddr *dest_addr,
			       socklen_t addrlen
			       )
{
  ptrdiff_t ret = 0;
  char dummy[len];
  
  if(sess->ssl == NULL){
    return -1;
  }

  pthread_mutex_lock(&sess->lock);
  pthread_mutex_unlock(&sess->lock);

  BIO* rbio = dtls_sess_get_rbio(sess);

  if(sess->state == DTLS_CONSTATE_ACTPASS){
    sess->state = DTLS_CONSTATE_PASS;
    SSL_set_accept_state(sess->ssl);
  }

  dtls_sess_send_pending(sess, fd, dest_addr, addrlen);

  BIO_write(rbio, buf, len);
  ret = SSL_read(sess->ssl, dummy, len);

  if(ret < 0){
    return ret;
  }

  dtls_sess_send_pending(sess, fd, dest_addr, addrlen);

  if(SSL_is_init_finished(sess->ssl)){
    sess->type = DTLS_CONTYPE_EXISTING;
  }

  return ret;
  
}

ptrdiff_t dtls_do_handshake(
			    dtls_sess* sess,
			    fd_t fd,
			    const struct sockaddr *dest_addr,
			    socklen_t addrlen
			    )
{
  /* If we are not acting as a client connecting to the remote side then
   * don't start the handshake as it will accomplish nothing and would conflict
   * with the handshake we receive from the remote side.
   */
  if(sess->ssl == NULL
     || dtls_sess_get_state(sess) != DTLS_CONSTATE_ACT){
    return 0;
  }
  SSL_do_handshake(sess->ssl);
  pthread_mutex_lock(&sess->lock);
  ptrdiff_t ret = dtls_sess_send_pending(sess, fd, dest_addr, addrlen);
  pthread_mutex_unlock(&sess->lock);
  return ret;
}

long dtls_sess_handle_timeout(
			      dtls_sess* sess,
			      fd_t fd,
			      const struct sockaddr *dest_addr,
			      socklen_t addrlen
			      )
{
  struct timeval timeout;
  DTLSv1_handle_timeout(sess->ssl);
  dtls_sess_send_pending(sess, fd, dest_addr, addrlen);
  if(!DTLSv1_get_timeout(sess->ssl, &timeout)) {
    return 0;
  }
  return timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
}


void dtls_sess_setup(dtls_sess* sess)
{
  if(sess->ssl == NULL || !SSL_is_init_finished(sess->ssl)){
    return;
  }

  SSL_clear(sess->ssl);
  if (sess->state == DTLS_CONSTATE_PASS) {
    SSL_set_accept_state(sess->ssl);
  } else {
    SSL_set_connect_state(sess->ssl);
  }
  sess->type = DTLS_CONTYPE_NEW;
}

srtp_key_material* srtp_get_key_material(dtls_sess* sess)
{
  if(!SSL_is_init_finished(sess->ssl)){
    return NULL;
  }

  srtp_key_material* km = calloc(1, sizeof(srtp_key_material));

  if(!SSL_export_keying_material(sess->ssl, km->material, sizeof(km->material), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)){
    key_material_free(km);
    return NULL;
  }

  km->ispassive = sess->state;
  
  return km;
}

void key_material_free(srtp_key_material* km)
{
  memset(km->material, 0, sizeof(km->material));
  free(km);
}
