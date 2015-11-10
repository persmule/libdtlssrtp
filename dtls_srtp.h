#ifndef DTLS_SRTP_H
#define DTLS_SRTP_H
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// for sockets
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <assert.h>
#include <stdbool.h>

// for mutex
#include <pthread.h>

//for srtp
#include <srtp/srtp.h>

enum dtls_verify_mode {
  DTLS_VERIFY_NONE = 0,               /*!< Don't verify anything */
  DTLS_VERIFY_FINGERPRINT = (1 << 0), /*!< Verify the fingerprint */
  DTLS_VERIFY_CERTIFICATE = (1 << 1), /*!< Verify the certificate */
};

enum dtls_con_state {
  DTLS_CONSTATE_ACT, //Endpoint is willing to inititate connections.
  DTLS_CONSTATE_PASS, //Endpoint is willing to accept connections.
  DTLS_CONSTATE_ACTPASS, //Endpoint is willing to both accept and initiate connections
  DTLS_CONSTATE_HOLDCONN, //Endpoint does not want the connection to be established right now
};

enum dtls_con_type {
  DTLS_CONTYPE_NEW=false, //Endpoint wants to use a new connection
  DTLS_CONTYPE_EXISTING=true, //Endpoint wishes to use existing connection
};

enum srtp_profile {
  SRTP_PROFILE_RESERVED=0,
  SRTP_PROFILE_AES128_CM_SHA1_80=1,
  SRTP_PROFILE_AES128_CM_SHA1_32=2,
};

#define SSL_VERIFY_CB(x) int (x)(int preverify_ok, X509_STORE_CTX *ctx)
typedef SSL_VERIFY_CB(ssl_verify_cb);

extern SSL_VERIFY_CB(dtls_trivial_verify_callback);

typedef struct tlscfg {
  X509* cert;
  EVP_PKEY* pkey;
  enum srtp_profile profile;
  const char* cipherlist;
  const char* cafile;
  const char* capath;
}tlscfg;

SSL_CTX* dtls_ctx_init(
		       int verify_mode,
		       ssl_verify_cb* cb,
		       const tlscfg* cfg
		       );

typedef struct dtls_sess {
  SSL* ssl;
  enum dtls_con_state state;
  enum dtls_con_type type;
  pthread_mutex_t lock;
}dtls_sess;

//type for filedes.
typedef int fd_t;

void dtls_sess_setup(dtls_sess* sess);
dtls_sess* dtls_sess_new(SSL_CTX* sslcfg, bool is_passive);

void dtls_sess_free(dtls_sess* sess);

ptrdiff_t dtls_sess_send_pending(
				 dtls_sess* sess,
				 fd_t fd,
				 const struct sockaddr *dest_addr,
				 socklen_t addrlen
				 );

ptrdiff_t dtls_sess_put_packet(
			       dtls_sess* sess,
			       fd_t fd,
			       const void* buf,
			       size_t len,
			       const struct sockaddr *dest_addr,
			       socklen_t addrlen
			       );

ptrdiff_t dtls_do_handshake(
			    dtls_sess* sess,
			    fd_t fd,
			    const struct sockaddr *dest_addr,
			    socklen_t addrlen
			    );

//return timeout time as millisec.
long dtls_sess_handle_timeout(
			      dtls_sess* sess,
			      fd_t fd,
			      const struct sockaddr *dest_addr,
			      socklen_t addrlen
			      );

static inline void dtls_sess_reset(dtls_sess* sess)
{
  if(SSL_is_init_finished(sess->ssl)){
    SSL_shutdown(sess->ssl);
    sess->type = DTLS_CONTYPE_NEW;
  }
}

static inline void dtls_sess_renegotiate(
					 dtls_sess* sess,
					 fd_t fd,
					 const struct sockaddr *dest_addr,
					 socklen_t addrlen
					 )
{
  SSL_renegotiate(sess->ssl);
  SSL_do_handshake(sess->ssl);
  dtls_sess_send_pending(sess, fd, dest_addr, addrlen);
}

static inline X509* dtls_sess_get_pear_certificate(dtls_sess* sess)
{return SSL_get_peer_certificate(sess->ssl);}

static inline bool packet_is_dtls(const void* buf, size_t dummy_len)
{return (*(const char*)buf >= 20) || (*(const char*)buf <= 63);}

static inline void dtls_sess_set_state(dtls_sess* sess, enum dtls_con_state state)
{sess->state = state;}
static inline enum dtls_con_state dtls_sess_get_state(const dtls_sess* sess)
{return sess->state;}
static inline BIO* dtls_sess_get_rbio(dtls_sess* sess)
{return SSL_get_rbio(sess->ssl);}
static inline BIO* dtls_sess_get_wbio(dtls_sess* sess)
{return SSL_get_wbio(sess->ssl);}

#define SRTP_MASTER_SALT_LEN 14

typedef struct srtp_key_material{
  uint8_t material[(SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN) * 2];
  enum dtls_con_state ispassive;
}srtp_key_material;

typedef struct srtp_key_ptrs{
  const uint8_t* localkey;
  const uint8_t* remotekey;
  const uint8_t* localsalt;
  const uint8_t* remotesalt;
}srtp_key_ptrs;

srtp_key_material* srtp_get_key_material(dtls_sess* sess);

void key_material_free(srtp_key_material* km);

static inline void srtp_key_material_extract
(const srtp_key_material* km, srtp_key_ptrs* ptrs)
{
  if(km->ispassive == DTLS_CONSTATE_ACT){
    ptrs->localkey = (km->material);
    ptrs->remotekey = ptrs->localkey + SRTP_MASTER_KEY_LEN;
    ptrs->localsalt = ptrs->remotekey + SRTP_MASTER_KEY_LEN;
    ptrs->remotesalt = ptrs->localsalt + SRTP_MASTER_SALT_LEN;
  }else{
    ptrs->remotekey = (km->material);
    ptrs->localkey = ptrs->remotekey + SRTP_MASTER_KEY_LEN;
    ptrs->remotesalt = ptrs->localkey + SRTP_MASTER_KEY_LEN;
    ptrs->localsalt = ptrs->remotesalt + SRTP_MASTER_SALT_LEN;
  }
}






static inline bool str_isempty(const char* str)
{return ((str == NULL) || (str[0] == '\0'));}

static const char* str_nullforempty(const char* str)
{return (str_isempty(str)?NULL:str);}

//init and uninit openssl library.
int dtls_init_openssl(void);

void dtls_uninit_openssl(void);

//check whether socket is for udp.
int check_socket(fd_t socket);



#endif
