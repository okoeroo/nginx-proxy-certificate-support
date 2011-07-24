
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_uint_t  engine;   /* unsigned  engine:1; */
} ngx_openssl_conf_t;


#ifdef RFC_3820_AND_CLASSIC_PROXY_SUPPORT
#include <openssl/x509v3.h>
#include <ctype.h>
#define PROXYCERTINFO_OID      "1.3.6.1.5.5.7.1.14"
#define OLD_PROXYCERTINFO_OID  "1.3.6.1.4.1.3536.1.222"
static size_t u_strlen (const unsigned char * s);
static time_t my_timegm(struct tm *tm);
static time_t grid_asn1TimeToTimeT(unsigned char *asn1time, size_t len);
static int grid_X509_verify_callback(int ok, X509_STORE_CTX *ctx);
static unsigned long grid_X509_knownCriticalExts(X509 *cert);
static unsigned long grid_verifyProxy(STACK_OF(X509) *certstack);
static int grid_verifyPathLenConstraints (STACK_OF(X509) * chain);
static int grid_check_issued_wrapper(X509_STORE_CTX *ctx,X509 *x,X509 *issuer);
#else
static int ngx_http_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
#endif /* RFC_3820_AND_CLASSIC_PROXY_SUPPORT */
static void ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where,
    int ret);
static void ngx_ssl_handshake_handler(ngx_event_t *ev);
static ngx_int_t ngx_ssl_handle_recv(ngx_connection_t *c, int n);
static void ngx_ssl_write_handler(ngx_event_t *wev);
static void ngx_ssl_read_handler(ngx_event_t *rev);
static void ngx_ssl_shutdown_handler(ngx_event_t *ev);
static void ngx_ssl_connection_error(ngx_connection_t *c, int sslerr,
    ngx_err_t err, char *text);
static void ngx_ssl_clear_error(ngx_log_t *log);

static ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone,
    void *data);
static int ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn,
    ngx_ssl_session_t *sess);
static ngx_ssl_session_t *ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn,
    u_char *id, int len, int *copy);
static void ngx_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
static void ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t n);
static void ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

static void *ngx_openssl_create_conf(ngx_cycle_t *cycle);
static char *ngx_openssl_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_openssl_exit(ngx_cycle_t *cycle);


static ngx_command_t  ngx_openssl_commands[] = {

    { ngx_string("ssl_engine"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_openssl_engine,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_openssl_module_ctx = {
    ngx_string("openssl"),
    ngx_openssl_create_conf,
    NULL
};


ngx_module_t  ngx_openssl_module = {
    NGX_MODULE_V1,
    &ngx_openssl_module_ctx,               /* module context */
    ngx_openssl_commands,                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    ngx_openssl_exit,                      /* exit master */
    NGX_MODULE_V1_PADDING
};


static long  ngx_ssl_protocols[] = {
    SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1,
    SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3,
    SSL_OP_NO_SSLv3,
    SSL_OP_NO_SSLv2,
    0,
};


int  ngx_ssl_connection_index;
int  ngx_ssl_server_conf_index;
int  ngx_ssl_session_cache_index;


ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
    OPENSSL_config(NULL);

    SSL_library_init();
    SSL_load_error_strings();

    ENGINE_load_builtin_engines();

    OpenSSL_add_all_algorithms();

    ngx_ssl_connection_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (ngx_ssl_connection_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "SSL_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_server_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (ngx_ssl_server_conf_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_session_cache_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);
    if (ngx_ssl_session_cache_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data)
{
    ssl->ctx = SSL_CTX_new(SSLv23_method());

    if (ssl->ctx == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "SSL_CTX_new() failed");
        return NGX_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_server_conf_index, data) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NGX_ERROR;
    }

    /* client side options */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);

    /* server side options */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

    /* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);

    if (ngx_ssl_protocols[protocols >> 1] != 0) {
        SSL_CTX_set_options(ssl->ctx, ngx_ssl_protocols[protocols >> 1]);
    }

    SSL_CTX_set_read_ahead(ssl->ctx, 1);

    SSL_CTX_set_info_callback(ssl->ctx, ngx_ssl_info_callback);

    return NGX_OK;
}




ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key)
{
    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (SSL_CTX_use_certificate_chain_file(ssl->ctx, (char *) cert->data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_certificate_chain_file(\"%s\") failed",
                      cert->data);
        return NGX_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, key, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl->ctx, (char *) key->data,
                                    SSL_FILETYPE_PEM)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_PrivateKey_file(\"%s\") failed", key->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    STACK_OF(X509_NAME)  *list;

#ifndef RFC_3820_AND_CLASSIC_PROXY_SUPPORT
    /* Classic behaviour */
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_http_ssl_verify_callback);
#else
    ssl->ctx->cert_store->check_issued = grid_check_issued_wrapper;
    /* SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, grid_X509_verify_callback); */
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, grid_X509_verify_callback);

    #if OPENSSL_VERSION_NUMBER < 0x00908000L
    X509_STORE_set_flags(SSL_CTX_get_cert_store(ssl->ctx), X509_V_FLAG_CRL_CHECK |
            X509_V_FLAG_CRL_CHECK_ALL );
    #else
    X509_STORE_set_flags(SSL_CTX_get_cert_store(ssl->ctx), X509_V_FLAG_CRL_CHECK |
            X509_V_FLAG_CRL_CHECK_ALL |
            X509_V_FLAG_ALLOW_PROXY_CERTS );
    #endif /* OPENSSL_VERSION_NUMBER < 0x00908000L */
    /* Max depth */
    /* SSL_CTX_set_verify_depth(ctx, MAXCHAINDEPTH) */
#endif


    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    #ifdef RFC_3820_AND_CLASSIC_PROXY_SUPPORT
    /* TODO: Clean up this hack and add a proper configuration option for a CA directory */
    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, "/etc/grid-security/certificates/")
        == 0)
    #else
    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
        == 0)
    #endif /* RFC_3820_AND_CLASSIC_PROXY_SUPPORT */
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_load_verify_locations(\"%s\") failed",
                      cert->data);
        return NGX_ERROR;
    }

    list = SSL_load_client_CA_file((char *) cert->data);

    if (list == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_load_client_CA_file(\"%s\") failed", cert->data);
        return NGX_ERROR;
    }


    /*
     * before 0.9.7h and 0.9.8 SSL_load_client_CA_file()
     * always leaved an error in the error queue
     */

    ERR_clear_error();

    SSL_CTX_set_client_CA_list(ssl->ctx, list);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
{
    X509_STORE   *store;
    X509_LOOKUP  *lookup;

    if (crl->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, crl, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);

    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NGX_ERROR;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());

    if (lookup == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_add_lookup() failed");
        return NGX_ERROR;
    }

    if (X509_LOOKUP_load_file(lookup, (char *) crl->data, X509_FILETYPE_PEM)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "X509_LOOKUP_load_file(\"%s\") failed", crl->data);
        return NGX_ERROR;
    }

    X509_STORE_set_flags(store,
                         X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    return NGX_OK;
}


#ifndef RFC_3820_AND_CLASSIC_PROXY_SUPPORT
/* This function is replaced by: grid_X509_verify_callback */ 
static int
ngx_http_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
#if (NGX_DEBUG)
    char              *subject, *issuer;
    int                err, depth;
    X509              *cert;
    X509_NAME         *sname, *iname;
    ngx_connection_t  *c;
    ngx_ssl_conn_t    *ssl_conn;

    ssl_conn = X509_STORE_CTX_get_ex_data(x509_store,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());

    c = ngx_ssl_get_connection(ssl_conn);

    cert = X509_STORE_CTX_get_current_cert(x509_store);
    err = X509_STORE_CTX_get_error(x509_store);
    depth = X509_STORE_CTX_get_error_depth(x509_store);

    sname = X509_get_subject_name(cert);
    subject = sname ? X509_NAME_oneline(sname, NULL, 0) : "(none)";

    iname = X509_get_issuer_name(cert);
    issuer = iname ? X509_NAME_oneline(iname, NULL, 0) : "(none)";

    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "verify:%d, error:%d, depth:%d, "
                   "subject:\"%s\",issuer: \"%s\"",
                   ok, err, depth, subject, issuer);

    if (sname) {
        OPENSSL_free(subject);
    }

    if (iname) {
        OPENSSL_free(issuer);
    }
#endif

    return 1;
}
#endif /* RFC_3820_AND_CLASSIC_PROXY_SUPPORT */


static void
ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where, int ret)
{
    ngx_connection_t  *c;

    if (where & SSL_CB_HANDSHAKE_START) {
        c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

        if (c->ssl->handshaked) {
            c->ssl->renegotiation = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL renegotiation");
        }
    }
}


ngx_int_t
ngx_ssl_generate_rsa512_key(ngx_ssl_t *ssl)
{
    RSA  *key;

    if (SSL_CTX_need_tmp_RSA(ssl->ctx) == 0) {
        return NGX_OK;
    }

    key = RSA_generate_key(512, RSA_F4, NULL, NULL);

    if (key) {
        SSL_CTX_set_tmp_rsa(ssl->ctx, key);

        RSA_free(key);

        return NGX_OK;
    }

    ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "RSA_generate_key(512) failed");

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    DH   *dh;
    BIO  *bio;

    /*
     * -----BEGIN DH PARAMETERS-----
     * MIGHAoGBALu8LcrYRnSQfEP89YDpz9vZWKP1aLQtSwju1OsPs1BMbAMCducQgAxc
     * y7qokiYUxb7spWWl/fHSh6K8BJvmd4Bg6RqSp1fjBI9osHb302zI8pul34HcLKcl
     * 7OZicMyaUDXYzs7vnqAnSmOrHlj6/UmI0PZdFGdX2gcd8EXP4WubAgEC
     * -----END DH PARAMETERS-----
     */

    static unsigned char dh1024_p[] = {
        0xBB, 0xBC, 0x2D, 0xCA, 0xD8, 0x46, 0x74, 0x90, 0x7C, 0x43, 0xFC, 0xF5,
        0x80, 0xE9, 0xCF, 0xDB, 0xD9, 0x58, 0xA3, 0xF5, 0x68, 0xB4, 0x2D, 0x4B,
        0x08, 0xEE, 0xD4, 0xEB, 0x0F, 0xB3, 0x50, 0x4C, 0x6C, 0x03, 0x02, 0x76,
        0xE7, 0x10, 0x80, 0x0C, 0x5C, 0xCB, 0xBA, 0xA8, 0x92, 0x26, 0x14, 0xC5,
        0xBE, 0xEC, 0xA5, 0x65, 0xA5, 0xFD, 0xF1, 0xD2, 0x87, 0xA2, 0xBC, 0x04,
        0x9B, 0xE6, 0x77, 0x80, 0x60, 0xE9, 0x1A, 0x92, 0xA7, 0x57, 0xE3, 0x04,
        0x8F, 0x68, 0xB0, 0x76, 0xF7, 0xD3, 0x6C, 0xC8, 0xF2, 0x9B, 0xA5, 0xDF,
        0x81, 0xDC, 0x2C, 0xA7, 0x25, 0xEC, 0xE6, 0x62, 0x70, 0xCC, 0x9A, 0x50,
        0x35, 0xD8, 0xCE, 0xCE, 0xEF, 0x9E, 0xA0, 0x27, 0x4A, 0x63, 0xAB, 0x1E,
        0x58, 0xFA, 0xFD, 0x49, 0x88, 0xD0, 0xF6, 0x5D, 0x14, 0x67, 0x57, 0xDA,
        0x07, 0x1D, 0xF0, 0x45, 0xCF, 0xE1, 0x6B, 0x9B
    };

    static unsigned char dh1024_g[] = { 0x02 };


    if (file->len == 0) {

        dh = DH_new();
        if (dh == NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "DH_new() failed");
            return NGX_ERROR;
        }

        dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
        dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

        if (dh->p == NULL || dh->g == NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "BN_bin2bn() failed");
            DH_free(dh);
            return NGX_ERROR;
        }

        SSL_CTX_set_tmp_dh(ssl->ctx, dh);

        DH_free(dh);

        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "r");
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return NGX_ERROR;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (dh == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_DHparams(\"%s\") failed", file->data);
        BIO_free(bio);
        return NGX_ERROR;
    }

    SSL_CTX_set_tmp_dh(ssl->ctx, dh);

    DH_free(dh);
    BIO_free(bio);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
{
    ngx_ssl_connection_t  *sc;

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->buffer = ((flags & NGX_SSL_BUFFER) != 0);

    sc->connection = SSL_new(ssl->ctx);

    if (sc->connection == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_new() failed");
        return NGX_ERROR;
    }

    if (SSL_set_fd(sc->connection, c->fd) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
        return NGX_ERROR;
    }

    if (flags & NGX_SSL_CLIENT) {
        SSL_set_connect_state(sc->connection);

    } else {
        SSL_set_accept_state(sc->connection);
    }

    if (SSL_set_ex_data(sc->connection, ngx_ssl_connection_index, c) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        return NGX_ERROR;
    }

    c->ssl = sc;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    if (session) {
        if (SSL_set_session(c->ssl->connection, session) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_session() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_handshake(ngx_connection_t *c)
{
    int        n, sslerr;
    ngx_err_t  err;

    ngx_ssl_clear_error(c->log);

    n = SSL_do_handshake(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == 1) {

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_DEBUG)
        {
        char         buf[129], *s, *d;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        const
#endif
        SSL_CIPHER  *cipher;

        cipher = SSL_get_current_cipher(c->ssl->connection);

        if (cipher) {
            SSL_CIPHER_description(cipher, &buf[1], 128);

            for (s = &buf[1], d = buf; *s; s++) {
                if (*s == ' ' && *d == ' ') {
                    continue;
                }

                if (*s == LF || *s == CR) {
                    continue;
                }

                *++d = *s;
            }

            if (*d != ' ') {
                d++;
            }

            *d = '\0';

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL: %s, cipher: \"%s\"",
                           SSL_get_version(c->ssl->connection), &buf[1]);

            if (SSL_session_reused(c->ssl->connection)) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "SSL reused session");
            }

        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL no shared ciphers");
        }
        }
#endif

        c->ssl->handshaked = 1;

        c->recv = ngx_ssl_recv;
        c->send = ngx_ssl_write;
        c->recv_chain = ngx_ssl_recv_chain;
        c->send_chain = ngx_ssl_send_chain;

        /* initial handshake done, disable renegotiation (CVE-2009-3555) */
        if (c->ssl->connection->s3) {
            c->ssl->connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }

        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, err,
                      "peer closed connection in SSL handshake");

        return NGX_ERROR;
    }

    c->read->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL handshake handler: %d", ev->write);

    if (ev->timedout) {
        c->ssl->handler(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
        return;
    }

    c->ssl->handler(c);
}


ssize_t
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl)
{
    u_char     *last;
    ssize_t     n, bytes;
    ngx_buf_t  *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {

        n = ngx_ssl_recv(c, last, b->end - last);

        if (n > 0) {
            last += n;
            bytes += n;

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {

            if (n == 0 || n == NGX_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}


ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;

    if (c->ssl->last == NGX_ERROR) {
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    ngx_ssl_clear_error(c->log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        n = SSL_read(c->ssl->connection, buf, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = ngx_ssl_handle_recv(c, n);

        if (c->ssl->last == NGX_OK) {

            size -= n;

            if (size == 0) {
                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            return bytes;
        }

        switch (c->ssl->last) {

        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NGX_ERROR:
            c->read->error = 1;

            /* fall thruogh */

        case NGX_AGAIN:
            return c->ssl->last;
        }
    }
}


static ngx_int_t
ngx_ssl_handle_recv(ngx_connection_t *c, int n)
{
    int        sslerr;
    ngx_err_t  err;

    if (c->ssl->renegotiation) {
        /*
         * disable renegotiation (CVE-2009-3555):
         * OpenSSL (at least up to 0.9.8l) does not handle disabled
         * renegotiation gracefully, so drop connection here
         */

        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "SSL renegotiation disabled");

        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        return NGX_ERROR;
    }

    if (n > 0) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer started SSL renegotiation");

        c->write->ready = 0;

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already the read event timer
         */

        if (c->ssl->saved_write_handler == NULL) {
            c->ssl->saved_write_handler = c->write->handler;
            c->write->handler = ngx_ssl_write_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "peer shutdown SSL cleanly");
        return NGX_DONE;
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_read() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c;

    c = wev->data;

    c->read->handler(c->read);
}


/*
 * OpenSSL has no SSL_writev() so we copy several bufs into our 16K buffer
 * before the SSL_write() call to decrease a SSL overhead.
 *
 * Besides for protocols such as HTTP it is possible to always buffer
 * the output to decrease a SSL overhead some more.
 */

ngx_chain_t *
ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int          n;
    ngx_uint_t   flush;
    ssize_t      send, size;
    ngx_buf_t   *buf;

    if (!c->ssl->buffer) {

        while (in) {
            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = ngx_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_AGAIN) {
                c->buffered |= NGX_SSL_BUFFERED;
                return in;
            }

            in->buf->pos += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }


    /* the maximum limit size is the maximum uint32_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_UINT32_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_UINT32_VALUE - ngx_pagesize;
    }

    buf = c->ssl->buf;

    if (buf == NULL) {
        buf = ngx_create_temp_buf(c->pool, NGX_SSL_BUFSIZE);
        if (buf == NULL) {
            return NGX_CHAIN_ERROR;
        }

        c->ssl->buf = buf;
    }

    if (buf->start == NULL) {
        buf->start = ngx_palloc(c->pool, NGX_SSL_BUFSIZE);
        if (buf->start == NULL) {
            return NGX_CHAIN_ERROR;
        }

        buf->pos = buf->start;
        buf->last = buf->start;
        buf->end = buf->start + NGX_SSL_BUFSIZE;
    }

    send = 0;
    flush = (in == NULL) ? 1 : 0;

    for ( ;; ) {

        while (in && buf->last < buf->end && send < limit) {
            if (in->buf->last_buf || in->buf->flush) {
                flush = 1;
            }

            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
                flush = 1;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %d", size);

            ngx_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;
            in->buf->pos += size;
            send += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        size = buf->last - buf->pos;

        if (!flush && buf->last < buf->end && c->ssl->buffer) {
            break;
        }

        n = ngx_ssl_write(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            c->buffered |= NGX_SSL_BUFFERED;
            return in;
        }

        buf->pos += n;
        c->sent += n;

        if (n < size) {
            break;
        }

        if (buf->pos == buf->last) {
            buf->pos = buf->start;
            buf->last = buf->start;
        }

        if (in == NULL || send == limit) {
            break;
        }
    }

    if (buf->pos < buf->last) {
        c->buffered |= NGX_SSL_BUFFERED;

    } else {
        c->buffered &= ~NGX_SSL_BUFFERED;
    }

    return in;
}


ssize_t
ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    ngx_err_t  err;

    ngx_ssl_clear_error(c->log);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %d", size);

    n = SSL_write(c->ssl->connection, data, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        return n;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer started SSL renegotiation");

        c->read->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = ngx_ssl_read_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_write() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    c->write->handler(c->write);
}


void
ngx_ssl_free_buffer(ngx_connection_t *c)
{
    if (c->ssl->buf && c->ssl->buf->start) {
        if (ngx_pfree(c->pool, c->ssl->buf->start) == NGX_OK) {
            c->ssl->buf->start = NULL;
        }
    }
}


ngx_int_t
ngx_ssl_shutdown(ngx_connection_t *c)
{
    int        n, sslerr, mode;
    ngx_err_t  err;

    if (c->timedout) {
        mode = SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN;

    } else {
        mode = SSL_get_shutdown(c->ssl->connection);

        if (c->ssl->no_wait_shutdown) {
            mode |= SSL_RECEIVED_SHUTDOWN;
        }

        if (c->ssl->no_send_shutdown) {
            mode |= SSL_SENT_SHUTDOWN;
        }
    }

    SSL_set_shutdown(c->ssl->connection, mode);

    ngx_ssl_clear_error(c->log);

    n = SSL_shutdown(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

    sslerr = 0;

    /* SSL_shutdown() never returns -1, on error it returns 0 */

    if (n != 1 && ERR_peek_error()) {
        sslerr = SSL_get_error(c->ssl->connection, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_error: %d", sslerr);
    }

    if (n == 1 || sslerr == 0 || sslerr == SSL_ERROR_ZERO_RETURN) {
        SSL_free(c->ssl->connection);
        c->ssl = NULL;

        return NGX_OK;
    }

    if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
        c->read->handler = ngx_ssl_shutdown_handler;
        c->write->handler = ngx_ssl_shutdown_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (sslerr == SSL_ERROR_WANT_READ) {
            ngx_add_timer(c->read, 30000);
        }

        return NGX_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_shutdown() failed");

    SSL_free(c->ssl->connection);
    c->ssl = NULL;

    return NGX_ERROR;
}


static void
ngx_ssl_shutdown_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_connection_handler_pt   handler;

    c = ev->data;
    handler = c->ssl->handler;

    if (ev->timedout) {
        c->timedout = 1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "SSL shutdown handler");

    if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
        return;
    }

    handler(c);
}


static void
ngx_ssl_connection_error(ngx_connection_t *c, int sslerr, ngx_err_t err,
    char *text)
{
    int         n;
    ngx_uint_t  level;

    level = NGX_LOG_CRIT;

    if (sslerr == SSL_ERROR_SYSCALL) {

        if (err == NGX_ECONNRESET
            || err == NGX_EPIPE
            || err == NGX_ENOTCONN
            || err == NGX_ETIMEDOUT
            || err == NGX_ECONNREFUSED
            || err == NGX_ENETDOWN
            || err == NGX_ENETUNREACH
            || err == NGX_EHOSTDOWN
            || err == NGX_EHOSTUNREACH)
        {
            switch (c->log_error) {

            case NGX_ERROR_IGNORE_ECONNRESET:
            case NGX_ERROR_INFO:
                level = NGX_LOG_INFO;
                break;

            case NGX_ERROR_ERR:
                level = NGX_LOG_ERR;
                break;

            default:
                break;
            }
        }

    } else if (sslerr == SSL_ERROR_SSL) {

        n = ERR_GET_REASON(ERR_peek_error());

            /* handshake failures */
        if (n == SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                     /*  129 */
            || n == SSL_R_DIGEST_CHECK_FAILED                        /*  149 */
            || n == SSL_R_LENGTH_MISMATCH                            /*  159 */
            || n == SSL_R_NO_CIPHERS_PASSED                          /*  182 */
            || n == SSL_R_NO_CIPHERS_SPECIFIED                       /*  183 */
            || n == SSL_R_NO_SHARED_CIPHER                           /*  193 */
            || n == SSL_R_RECORD_LENGTH_MISMATCH                     /*  213 */
            || n == SSL_R_UNEXPECTED_MESSAGE                         /*  244 */
            || n == SSL_R_UNEXPECTED_RECORD                          /*  245 */
            || n == SSL_R_UNKNOWN_ALERT_TYPE                         /*  246 */
            || n == SSL_R_UNKNOWN_PROTOCOL                           /*  252 */
            || n == SSL_R_WRONG_VERSION_NUMBER                       /*  267 */
            || n == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        /*  281 */
            || n == 1000 /* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
            || n == SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             /* 1010 */
            || n == SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 /* 1020 */
            || n == SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              /* 1021 */
            || n == SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                /* 1022 */
            || n == SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          /* 1030 */
            || n == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              /* 1040 */
            || n == SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 /* 1041 */
            || n == SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                /* 1042 */
            || n == SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        /* 1043 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            /* 1044 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            /* 1045 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            /* 1046 */
            || n == SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              /* 1047 */
            || n == SSL_R_TLSV1_ALERT_UNKNOWN_CA                     /* 1048 */
            || n == SSL_R_TLSV1_ALERT_ACCESS_DENIED                  /* 1049 */
            || n == SSL_R_TLSV1_ALERT_DECODE_ERROR                   /* 1050 */
            || n == SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  /* 1051 */
            || n == SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             /* 1060 */
            || n == SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               /* 1070 */
            || n == SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          /* 1071 */
            || n == SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 /* 1080 */
            || n == SSL_R_TLSV1_ALERT_USER_CANCELLED                 /* 1090 */
            || n == SSL_R_TLSV1_ALERT_NO_RENEGOTIATION)              /* 1100 */
        {
            switch (c->log_error) {

            case NGX_ERROR_IGNORE_ECONNRESET:
            case NGX_ERROR_INFO:
                level = NGX_LOG_INFO;
                break;

            case NGX_ERROR_ERR:
                level = NGX_LOG_ERR;
                break;

            default:
                break;
            }
        }
    }

    ngx_ssl_error(level, c->log, err, text);
}


static void
ngx_ssl_clear_error(ngx_log_t *log)
{
    while (ERR_peek_error()) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "ignoring stale global SSL error");
    }

    ERR_clear_error();
}


void ngx_cdecl
ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, char *fmt, ...)
{
    u_long    n;
    va_list   args;
    u_char   *p, *last;
    u_char    errstr[NGX_MAX_CONF_ERRSTR];

    last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = ngx_vslprintf(errstr, last - 1, fmt, args);
    va_end(args);

    p = ngx_cpystrn(p, (u_char *) " (SSL:", last - p);

    for ( ;; ) {

        n = ERR_get_error();

        if (n == 0) {
            break;
        }

        if (p >= last) {
            continue;
        }

        *p++ = ' ';

        ERR_error_string_n(n, (char *) p, last - p);

        while (p < last && *p) {
            p++;
        }
    }

    ngx_log_error(level, log, err, "%s)", errstr);
}


ngx_int_t
ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout)
{
    long  cache_mode;

    if (builtin_session_cache == NGX_SSL_NO_SCACHE) {
        SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);
        return NGX_OK;
    }

    SSL_CTX_set_session_id_context(ssl->ctx, sess_ctx->data, sess_ctx->len);

    if (builtin_session_cache == NGX_SSL_NONE_SCACHE) {

        /*
         * If the server explicitly says that it does not support
         * session reuse (see SSL_SESS_CACHE_OFF above), then
         * Outlook Express fails to upload a sent email to
         * the Sent Items folder on the IMAP server via a separate IMAP
         * connection in the background. Therefore we have a special
         * mode (SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL_STORE)
         * where the server pretends that it supports session reuse,
         * but it does not actually store any session.
         */

        SSL_CTX_set_session_cache_mode(ssl->ctx,
                                       SSL_SESS_CACHE_SERVER
                                       |SSL_SESS_CACHE_NO_AUTO_CLEAR
                                       |SSL_SESS_CACHE_NO_INTERNAL_STORE);

        SSL_CTX_sess_set_cache_size(ssl->ctx, 1);

        return NGX_OK;
    }

    cache_mode = SSL_SESS_CACHE_SERVER;

    if (shm_zone && builtin_session_cache == NGX_SSL_NO_BUILTIN_SCACHE) {
        cache_mode |= SSL_SESS_CACHE_NO_INTERNAL;
    }

    SSL_CTX_set_session_cache_mode(ssl->ctx, cache_mode);

    if (builtin_session_cache != NGX_SSL_NO_BUILTIN_SCACHE) {

        if (builtin_session_cache != NGX_SSL_DFLT_BUILTIN_SCACHE) {
            SSL_CTX_sess_set_cache_size(ssl->ctx, builtin_session_cache);
        }
    }

    SSL_CTX_set_timeout(ssl->ctx, (long) timeout);

    if (shm_zone) {
        shm_zone->init = ngx_ssl_session_cache_init;

        SSL_CTX_sess_set_new_cb(ssl->ctx, ngx_ssl_new_session);
        SSL_CTX_sess_set_get_cb(ssl->ctx, ngx_ssl_get_cached_session);
        SSL_CTX_sess_set_remove_cb(ssl->ctx, ngx_ssl_remove_session);

        if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_session_cache_index, shm_zone)
            == 0)
        {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_set_ex_data() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                    len;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_session_cache_t  *cache;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    if (shm_zone->shm.exists) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    cache = ngx_slab_alloc(shpool, sizeof(ngx_ssl_session_cache_t));
    if (cache == NULL) {
        return NGX_ERROR;
    }

    shpool->data = cache;
    shm_zone->data = cache;

    ngx_rbtree_init(&cache->session_rbtree, &cache->sentinel,
                    ngx_ssl_session_rbtree_insert_value);

    ngx_queue_init(&cache->expire_queue);

    len = sizeof(" in SSL session shared cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in SSL session shared cache \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


/*
 * The length of the session id is 16 bytes for SSLv2 sessions and
 * between 1 and 32 bytes for SSLv3/TLSv1, typically 32 bytes.
 * It seems that the typical length of the external ASN1 representation
 * of a session is 118 or 119 bytes for SSLv3/TSLv1.
 *
 * Thus on 32-bit platforms we allocate separately an rbtree node,
 * a session id, and an ASN1 representation, they take accordingly
 * 64, 32, and 128 bytes.
 *
 * On 64-bit platforms we allocate separately an rbtree node + session_id,
 * and an ASN1 representation, they take accordingly 128 and 128 bytes.
 *
 * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
 * so they are outside the code locked by shared pool mutex
 */

static int
ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    int                       len;
    u_char                   *p, *id, *cached_sess;
    uint32_t                  hash;
    SSL_CTX                  *ssl_ctx;
    ngx_shm_zone_t           *shm_zone;
    ngx_connection_t         *c;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;
    u_char                    buf[NGX_SSL_MAX_SESSION_SIZE];

    len = i2d_SSL_SESSION(sess, NULL);

    /* do not cache too big session */

    if (len > (int) NGX_SSL_MAX_SESSION_SIZE) {
        return 0;
    }

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    c = ngx_ssl_get_connection(ssl_conn);

    ssl_ctx = SSL_get_SSL_CTX(ssl_conn);
    shm_zone = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index);

    cache = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* drop one or two expired sessions */
    ngx_ssl_expire_sessions(cache, shpool, 1);

    cached_sess = ngx_slab_alloc_locked(shpool, len);

    if (cached_sess == NULL) {

        /* drop the oldest non-expired session and try once more */

        ngx_ssl_expire_sessions(cache, shpool, 0);

        cached_sess = ngx_slab_alloc_locked(shpool, len);

        if (cached_sess == NULL) {
            sess_id = NULL;
            goto failed;
        }
    }

    sess_id = ngx_slab_alloc_locked(shpool, sizeof(ngx_ssl_sess_id_t));
    if (sess_id == NULL) {
        goto failed;
    }

#if (NGX_PTR_SIZE == 8)

    id = sess_id->sess_id;

#else

    id = ngx_slab_alloc_locked(shpool, sess->session_id_length);
    if (id == NULL) {
        goto failed;
    }

#endif

    ngx_memcpy(cached_sess, buf, len);

    ngx_memcpy(id, sess->session_id, sess->session_id_length);

    hash = ngx_crc32_short(sess->session_id, sess->session_id_length);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl new session: %08XD:%d:%d",
                   hash, sess->session_id_length, len);

    sess_id->node.key = hash;
    sess_id->node.data = (u_char) sess->session_id_length;
    sess_id->id = id;
    sess_id->len = len;
    sess_id->session = cached_sess;

    sess_id->expire = ngx_time() + SSL_CTX_get_timeout(ssl_ctx);

    ngx_queue_insert_head(&cache->expire_queue, &sess_id->queue);

    ngx_rbtree_insert(&cache->session_rbtree, &sess_id->node);

    ngx_shmtx_unlock(&shpool->mutex);

    return 0;

failed:

    if (cached_sess) {
        ngx_slab_free_locked(shpool, cached_sess);
    }

    if (sess_id) {
        ngx_slab_free_locked(shpool, sess_id);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                  "could not add new SSL session to the session cache");

    return 0;
}


static ngx_ssl_session_t *
ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn, u_char *id, int len,
    int *copy)
{
#if OPENSSL_VERSION_NUMBER >= 0x0090707fL
    const
#endif
    u_char                   *p;
    uint32_t                  hash;
    ngx_int_t                 rc;
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_connection_t         *c;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_ssl_session_t        *sess;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;
    u_char                    buf[NGX_SSL_MAX_SESSION_SIZE];

    c = ngx_ssl_get_connection(ssl_conn);

    hash = ngx_crc32_short(id, (size_t) len);
    *copy = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl get session: %08XD:%d", hash, len);

    shm_zone = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl_conn),
                                   ngx_ssl_session_cache_index);

    cache = shm_zone->data;

    sess = NULL;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        do {
            sess_id = (ngx_ssl_sess_id_t *) node;

            rc = ngx_memn2cmp(id, sess_id->id,
                              (size_t) len, (size_t) node->data);
            if (rc == 0) {

                if (sess_id->expire > ngx_time()) {
                    ngx_memcpy(buf, sess_id->session, sess_id->len);

                    ngx_shmtx_unlock(&shpool->mutex);

                    p = buf;
                    sess = d2i_SSL_SESSION(NULL, &p, sess_id->len);

                    return sess;
                }

                ngx_queue_remove(&sess_id->queue);

                ngx_rbtree_delete(&cache->session_rbtree, node);

                ngx_slab_free_locked(shpool, sess_id->session);
#if (NGX_PTR_SIZE == 4)
                ngx_slab_free_locked(shpool, sess_id->id);
#endif
                ngx_slab_free_locked(shpool, sess_id);

                sess = NULL;

                goto done;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

done:

    ngx_shmtx_unlock(&shpool->mutex);

    return sess;
}


void
ngx_ssl_remove_cached_session(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
     SSL_CTX_remove_session(ssl, sess);

     ngx_ssl_remove_session(ssl, sess);
}


static void
ngx_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
    size_t                    len;
    u_char                   *id;
    uint32_t                  hash;
    ngx_int_t                 rc;
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;

    shm_zone = SSL_CTX_get_ex_data(ssl, ngx_ssl_session_cache_index);

    if (shm_zone == NULL) {
        return;
    }

    cache = shm_zone->data;

    id = sess->session_id;
    len = (size_t) sess->session_id_length;

    hash = ngx_crc32_short(id, len);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "ssl remove session: %08XD:%uz", hash, len);

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        do {
            sess_id = (ngx_ssl_sess_id_t *) node;

            rc = ngx_memn2cmp(id, sess_id->id, len, (size_t) node->data);

            if (rc == 0) {

                ngx_queue_remove(&sess_id->queue);

                ngx_rbtree_delete(&cache->session_rbtree, node);

                ngx_slab_free_locked(shpool, sess_id->session);
#if (NGX_PTR_SIZE == 4)
                ngx_slab_free_locked(shpool, sess_id->id);
#endif
                ngx_slab_free_locked(shpool, sess_id);

                goto done;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

done:

    ngx_shmtx_unlock(&shpool->mutex);
}


static void
ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t n)
{
    time_t              now;
    ngx_queue_t        *q;
    ngx_ssl_sess_id_t  *sess_id;

    now = ngx_time();

    while (n < 3) {

        if (ngx_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = ngx_queue_last(&cache->expire_queue);

        sess_id = ngx_queue_data(q, ngx_ssl_sess_id_t, queue);

        if (n++ != 0 && sess_id->expire > now) {
            return;
        }

        ngx_queue_remove(q);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                       "expire session: %08Xi", sess_id->node.key);

        ngx_rbtree_delete(&cache->session_rbtree, &sess_id->node);

        ngx_slab_free_locked(shpool, sess_id->session);
#if (NGX_PTR_SIZE == 4)
        ngx_slab_free_locked(shpool, sess_id->id);
#endif
        ngx_slab_free_locked(shpool, sess_id);
    }
}


static void
ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    ngx_ssl_sess_id_t   *sess_id, *sess_id_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sess_id = (ngx_ssl_sess_id_t *) node;
            sess_id_temp = (ngx_ssl_sess_id_t *) temp;

            p = (ngx_memn2cmp(sess_id->id, sess_id_temp->id,
                              (size_t) node->data, (size_t) temp->data)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


void
ngx_ssl_cleanup_ctx(void *data)
{
    ngx_ssl_t  *ssl = data;

    SSL_CTX_free(ssl->ctx);
}


ngx_int_t
ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->data = (u_char *) SSL_get_version(c->ssl->connection);
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->data = (u_char *) SSL_get_cipher_name(c->ssl->connection);
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    int           len;
    u_char       *p, *buf;
    SSL_SESSION  *sess;

    sess = SSL_get0_session(c->ssl->connection);

    len = i2d_SSL_SESSION(sess, NULL);

    buf = ngx_alloc(len, c->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    s->len = 2 * len;
    s->data = ngx_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        ngx_free(buf);
        return NGX_ERROR;
    }

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    ngx_hex_dump(s->data, buf, len);

    ngx_free(buf);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    size_t   len;
    BIO     *bio;
    X509    *cert;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PEM_write_bio_X509() failed");
        goto failed;
    }

    len = BIO_pending(bio);
    s->len = len;

    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, len);

    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    u_char      *p;
    size_t       len;
    ngx_uint_t   i;
    ngx_str_t    cert;

    if (ngx_ssl_get_raw_certificate(c, pool, &cert) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cert.len == 0) {
        s->len = 0;
        return NGX_OK;
    }

    len = cert.len - 1;

    for (i = 0; i < cert.len - 1; i++) {
        if (cert.data[i] == LF) {
            len++;
        }
    }

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    p = s->data;

    for (i = 0; i < cert.len - 1; i++) {
        *p++ = cert.data[i];
        if (cert.data[i] == LF) {
            *p++ = '\t';
        }
    }

    return NGX_OK;
}


/* TODO */
ngx_int_t
ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return NGX_OK;
}


/* TODO */
ngx_int_t
ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    name = X509_get_issuer_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    size_t   len;
    X509    *cert;
    BIO     *bio;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));
    len = BIO_pending(bio);

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return NGX_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    X509  *cert;

    if (SSL_get_verify_result(c->ssl->connection) != X509_V_OK) {
        ngx_str_set(s, "FAILED");
        return NGX_OK;
    }

    cert = SSL_get_peer_certificate(c->ssl->connection);

    if (cert) {
        ngx_str_set(s, "SUCCESS");

    } else {
        ngx_str_set(s, "NONE");
    }

    X509_free(cert);

    return NGX_OK;
}


static void *
ngx_openssl_create_conf(ngx_cycle_t *cycle)
{
    ngx_openssl_conf_t  *oscf;

    oscf = ngx_pcalloc(cycle->pool, sizeof(ngx_openssl_conf_t));
    if (oscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     oscf->engine = 0;
     */

    return oscf;
}


static char *
ngx_openssl_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_openssl_conf_t *oscf = conf;

    ENGINE     *engine;
    ngx_str_t  *value;

    if (oscf->engine) {
        return "is duplicate";
    }

    oscf->engine = 1;

    value = cf->args->elts;

    engine = ENGINE_by_id((const char *) value[1].data);

    if (engine == NULL) {
        ngx_ssl_error(NGX_LOG_WARN, cf->log, 0,
                      "ENGINE_by_id(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
        ngx_ssl_error(NGX_LOG_WARN, cf->log, 0,
                      "ENGINE_set_default(\"%V\", ENGINE_METHOD_ALL) failed",
                      &value[1]);

        ENGINE_free(engine);

        return NGX_CONF_ERROR;
    }

    ENGINE_free(engine);

    return NGX_CONF_OK;
}


static void
ngx_openssl_exit(ngx_cycle_t *cycle)
{
    EVP_cleanup();
    ENGINE_cleanup();
}


#ifdef RFC_3820_AND_CLASSIC_PROXY_SUPPORT
/* ASN1 time string (in a char *) to time_t */
/**
 *  (Use ASN1_STRING_data() to convert ASN1_GENERALIZEDTIME to char * if
 *   necessary)
 */
static size_t
u_strlen (const unsigned char * s) {
    size_t i;
    for (i = 0; s[i] != '\0'; i++) ;
    return i;
}

/**
 * Note that timegm() is non-standard. Linux manpage advices the following
 * substition instead.
 */
static time_t
my_timegm(struct tm *tm)
{
    time_t ret;
    char *tz;

    tz = getenv("TZ");
    setenv("TZ", "", 1);
    tzset();
    ret = mktime(tm);
    if (tz)
        setenv("TZ", tz, 1);
    else
        unsetenv("TZ");
    tzset();

    return ret;
}

static time_t
grid_asn1TimeToTimeT(unsigned char *asn1time, size_t len) {
   char   zone;
   struct tm time_tm;

   if (len == 0) len = u_strlen(asn1time);

   if ((len != 13) && (len != 15)) return 0; /* dont understand */

   if ((len == 13) &&
       ((sscanf((char *) asn1time, "%02d%02d%02d%02d%02d%02d%c",
         &(time_tm.tm_year),
         &(time_tm.tm_mon),
         &(time_tm.tm_mday),
         &(time_tm.tm_hour),
         &(time_tm.tm_min),
         &(time_tm.tm_sec),
         &zone) != 7) || (zone != 'Z'))) return 0; /* dont understand */

   if ((len == 15) &&
       ((sscanf((char *) asn1time, "20%02d%02d%02d%02d%02d%02d%c",
         &(time_tm.tm_year),
         &(time_tm.tm_mon),
         &(time_tm.tm_mday),
         &(time_tm.tm_hour),
         &(time_tm.tm_min),
         &(time_tm.tm_sec),
         &zone) != 7) || (zone != 'Z'))) return 0; /* dont understand */

   /* time format fixups */

   if (time_tm.tm_year < 90) time_tm.tm_year += 100;
   --(time_tm.tm_mon);

   return my_timegm(&time_tm);
}


static unsigned long
grid_X509_knownCriticalExts(X509 *cert) {
   int  i;
   char s[80];
   X509_EXTENSION *ex;

   for (i = 0; i < X509_get_ext_count(cert); ++i) {
        ex = X509_get_ext(cert, i);

        if (X509_EXTENSION_get_critical(ex) && !X509_supported_extension(ex)) {
            OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);

            if (strcmp(s, PROXYCERTINFO_OID) == 0) return X509_V_OK;
            if (strcmp(s, OLD_PROXYCERTINFO_OID) == 0) return X509_V_OK;

            return X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
          }
      }

   return X509_V_OK;
}

/* Check if certificate can be used as a CA to sign standard X509 certs */
/*
 *  Return 1 if true; 0 if not.
 */
int grid_x509IsCA(X509 *cert)
{
    int idret;

    /* final argument to X509_check_purpose() is whether to check for CAness */
    idret = X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 1);
    if (idret == 1)
        return 1;
    else if (idret == 0)
        return 0;
    else {
        /* Log( L_WARN, "Purpose warning code = %d\n", idret ); */
        return 1;
    }
}


/******************************************************************************
Function:   grid_verifyProxy
Description:
    Tries to verify the proxies in the certstack
******************************************************************************/
static unsigned long
grid_verifyProxy( STACK_OF(X509) *certstack ) {
    /* char    *oper = "Verifying proxy"; */

    int      i = 0;
    int      serialLen, j = 0;
    X509    *cert = NULL;
    time_t   now = time((time_t *)NULL);
    size_t   len = 0;             /* Lengths of issuer and cert DN */
    size_t   len2 = 0;            /* Lengths of issuer and cert DN */
    int      prevIsLimited = 0;   /* previous cert was proxy and limited */
    char    *cert_DN = NULL;      /* Pointer to current-certificate-in-certstack's DN */
    char    *issuer_DN = NULL;    /* Pointer to issuer-of-current-cert-in-certstack's DN */
    char    *proxy_part_DN = NULL;
    int      depth = sk_X509_num (certstack);
    int      amount_of_CAs = 0;
    int      is_old_style_proxy = 0;
    int      is_limited_proxy = 0;
    ASN1_INTEGER   *cert_Serial = NULL;
    ASN1_INTEGER   *issuer_Serial = NULL;
    unsigned char   serialNumberDER[127];
    unsigned char   serialStr[255];
    unsigned char  *temp;


    /* And there was (current) time... */
    time(&now);

    /* How many CA certs are there in the certstack? */
    for (i = 0; i < depth; i++) {
        if (grid_x509IsCA(sk_X509_value(certstack, i)))
            amount_of_CAs++;
    }

    if ((amount_of_CAs + 2) > depth) {
        if ((depth - amount_of_CAs) > 0) {
            /* Log( L_WARN, "No proxy certificate in certificate stack to check." ); */
            return X509_V_OK;
        } else {
            /* Error( oper, "No personal certificate (neither proxy or user certificate) found in the certficiate stack." ); */
            return X509_V_ERR_APPLICATION_VERIFICATION;
        }
    }

    /* Changed this value to start checking the proxy and such and
       to skip the CA and the user_cert
    */
    for (i = depth - (amount_of_CAs + 2); i >= 0; i--) {
        /* Check for X509 certificate and point to it with 'cert' */
        if ( (cert = sk_X509_value(certstack, i)) != NULL ) {
            cert_DN   = X509_NAME_oneline( X509_get_subject_name( cert), NULL, 0);
            issuer_DN = X509_NAME_oneline( X509_get_issuer_name( cert ), NULL, 0);
            len       = strlen( cert_DN );
            len2      = strlen( issuer_DN );

            if (now < grid_asn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert)),0)) {
                /* Error( oper, "Proxy certificate is not yet valid." ); */
                return X509_V_ERR_CERT_NOT_YET_VALID;
            }

            if (now > grid_asn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert)),0)) {
                /* Error( oper, "Proxy certificate expired." ); */
/* error will be caught later by x509_verify
                return X509_V_ERR_CERT_HAS_EXPIRED;
*/
            }

            /* User not allowed to sign shortened DN */
            if (len2 > len) {
                /* Error( oper, "It is not allowed to sign a shorthened DN."); */
                return X509_V_ERR_APPLICATION_VERIFICATION;
            }

            /* Proxy subject must begin with issuer. */
            if (strncmp(cert_DN, issuer_DN, len2) != 0) {
                /* Error( oper, "Proxy subject must begin with the issuer."); */
                return X509_V_ERR_APPLICATION_VERIFICATION;
            }

            /* Set pointer to end of base DN in cert_DN */
            proxy_part_DN = &cert_DN[len2];

            /* First attempt at support for Old and New style GSI
               proxies: /CN=anything is ok for now */
            if (strncmp(proxy_part_DN, "/CN=", 4) != 0) {
                /* Error( oper, "Could not find a /CN= structure in the DN, thus it is not a proxy."); */
                return X509_V_ERR_APPLICATION_VERIFICATION;
            }

            if (strncmp(proxy_part_DN, "/CN=proxy", 9) == 0) {
                /* Log( L_INFO, "Current certificate is an old style proxy."); */
                is_old_style_proxy = 1;
                is_limited_proxy = 0;
            }
            else if (strncmp(proxy_part_DN, "/CN=limited proxy", 17) == 0) {
                /* Log( L_INFO, "Current certificate is an old limited style proxy."); */
                is_old_style_proxy = 1;
                is_limited_proxy = 1;
            } else {
                /* Log( L_INFO, "Current certificate is a GSI/RFC3820 proxy."); */
            }

            if ( is_old_style_proxy ) {
                cert_Serial = X509_get_serialNumber( cert );
                temp = serialNumberDER;
                serialLen = i2c_ASN1_INTEGER( cert_Serial, &temp );
                bzero( serialStr, sizeof( serialStr) );
                temp = serialStr;
                for (j = 0; j < serialLen; j++) {
                    sprintf((char *) temp, "%02X", serialNumberDER[j] );
                    temp = temp + 2;
                }
                /* Log( L_DEBUG, "Serial number: %s", serialStr); */

                issuer_Serial = X509_get_serialNumber( sk_X509_value(certstack, i+1));
                temp = serialNumberDER;
                serialLen = i2c_ASN1_INTEGER( issuer_Serial, &temp );
                bzero( serialStr, sizeof( serialStr) );
                temp = serialStr;
                for (j = 0; j < serialLen; j++) {
                    sprintf((char *) temp, "%02X", serialNumberDER[j] );
                    temp = temp + 2;
                }
                /* Log( L_DEBUG, "Issuer serial number: %s", serialStr); */
                if (cert_Serial && issuer_Serial) {
                    if ( ASN1_INTEGER_cmp( cert_Serial, issuer_Serial ) ) {
                        /* Log( L_WARN, "Serial numbers do not match." ); */
                    }
                }
            }

            if ( is_limited_proxy ) {
                prevIsLimited = 1;
                /* if (i > 0) Log( L_WARN, "Found limited proxy."); */
            } else {
                if (prevIsLimited) {
                    /* Error( oper, "Proxy chain integrity error. Previous proxy in chain was limited, but this one is a regular proxy."); */
                    return X509_V_ERR_APPLICATION_VERIFICATION;
                }
            }

            if (cert_DN) free(cert_DN);
            if (issuer_DN) free(issuer_DN);
        }
    }

    return X509_V_OK;
}



/******************************************************************************
Function:   grid_verifyPathLenConstraints
Description:
            This function will check the certificate chain on CA based (RFC5280) 
            and RFC3820 Proxy based Path Length Constraints.
Parameters:
    chain of certificates
Returns:
    0       : Not ok, failure in the verification or the verification failed
    1       : Ok, verification has succeeded and positive
******************************************************************************/
static int
grid_verifyPathLenConstraints (STACK_OF(X509) * chain)
{
    /* char *oper = "grid_verifyPathLenConstraints"; */
    X509 * cert = NULL;
    int i, depth;
    size_t j;
    enum {
          NONE      = 0,
          CA        = 1,
          EEC       = 2,
          GT2_PROXY = 4,
          RFC_PROXY = 8
         } curr_cert_type = NONE, expe_cert_type = CA|EEC|RFC_PROXY|GT2_PROXY;
    char * cert_subjectdn = NULL;

    int ca_path_len_countdown    = -1;
    int proxy_path_len_countdown = -1;

    /* No chain, no game */
    if (!chain) {
        /* Error( oper, "No certificate chain detected."); */
        goto failure;
    }

    /* Go through the list, from the CA(s) down through the EEC to the final delegation */
    depth = sk_X509_num (chain);
    for (i=depth-1; i >= 0; --i) { 
        if ((cert = sk_X509_value(chain, i))) {
            /* Init to None, indicating not to have identified it yet */
            curr_cert_type = NONE;

            /* Extract Subject DN - Needs free */
            if (!(cert_subjectdn = X509_NAME_oneline (X509_get_subject_name (cert), NULL, 0))) {
                /* Error (oper, "Couldn't get the subject DN from the certificate at depth %d\n"); */
                goto failure;
            }

            /* Log (L_DEBUG, "\tCert here is: %s\n", cert_subjectdn); */

            /* Is it a CA certificate */
            if (grid_x509IsCA(cert)) {
                curr_cert_type = CA;
            } else {
#if OPENSSL_VERSION_NUMBER < 0x00908000L
                /* Is the certificate an RFC 3820 proxy? */
                if (cert->ex_flags & EXFLAG_PROXY) {
                    curr_cert_type = RFC_PROXY;
                } else {
#endif
                    /* Is the certificate an old style / classic proxy? */

                    /* Lower case the Subject DN */
                    for (j = 0; j < strlen(cert_subjectdn); j++) {
                        cert_subjectdn[j] = tolower(cert_subjectdn[j]);
                    }

                    /* Does the subject DN have the old style proxy certifcate signature /cn=proxy substring? */
                    if (strstr(cert_subjectdn, "/cn=proxy")) {
                        curr_cert_type = GT2_PROXY;
                    } else {
                        /* If all else fails, it's an EEC certificate */
                        curr_cert_type = EEC;
                    }
#if OPENSSL_VERSION_NUMBER < 0x00908000L
                }
#endif
            }


            /* Expectation management */
            if (!((expe_cert_type & curr_cert_type) == curr_cert_type)) {
                /* Failed to comply with the expectations! */
/*
                if (expe_cert_type == CA)
                    Error(oper, "Certificate chain not build in the right order. Got a %s certificate, but expected a CA certificate at depth %d of %d\n",
                                curr_cert_type == CA ? "CA" : curr_cert_type == EEC ? "EEC" : curr_cert_type == GT2_PROXY ? "old-style Proxy" : curr_cert_type == RFC_PROXY ? "RFC3820 Proxy" : "Unknown", i, depth);
                if (expe_cert_type == EEC)
                    Error(oper, "Certificate chain not build in the right order. Got a %s certificate, but expected a EEC certificate at depth %d of %d\n",
                                curr_cert_type == CA ? "CA" : curr_cert_type == EEC ? "EEC" : curr_cert_type == GT2_PROXY ? "old-style Proxy" : curr_cert_type == RFC_PROXY ? "RFC3820 Proxy" : "Unknown", i, depth);
                if (expe_cert_type == GT2_PROXY)
                    Error(oper, "Certificate chain not build in the right order. Got a %s certificate, but expected an old-style Proxy certificate at depth %d of %d\n",
                                curr_cert_type == CA ? "CA" : curr_cert_type == EEC ? "EEC" : curr_cert_type == GT2_PROXY ? "old-style Proxy" : curr_cert_type == RFC_PROXY ? "RFC3820 Proxy" : "Unknown", i, depth);
                if (expe_cert_type == RFC_PROXY)
                    Error(oper, "Certificate chain not build in the right order. Got a %s certificate, but expected an RFC3820 Proxy certificate at depth %d of %d\n",
                                curr_cert_type == CA ? "CA" : curr_cert_type == EEC ? "EEC" : curr_cert_type == GT2_PROXY ? "old-style Proxy" : curr_cert_type == RFC_PROXY ? "RFC3820 Proxy" : "Unknown", i, depth);
                if (expe_cert_type & (RFC_PROXY | GT2_PROXY))
                    Error(oper, "Certificate chain not build in the right order. Got a %s certificate, but expected an RFC3820 Proxy or old-style Proxy certificate at depth %d of %d\n",
                                curr_cert_type == CA ? "CA" : curr_cert_type == EEC ? "EEC" : curr_cert_type == GT2_PROXY ? "old-style Proxy" : curr_cert_type == RFC_PROXY ? "RFC3820 Proxy" : "Unknown", i, depth);
                if (expe_cert_type & (CA | EEC))
                    Error(oper, "Certificate chain not build in the right order. Got a %s certificate, but expected a CA or EEC certificate at depth %d of %d\n",
                                curr_cert_type == CA ? "CA" : curr_cert_type == EEC ? "EEC" : curr_cert_type == GT2_PROXY ? "old-style Proxy" : curr_cert_type == RFC_PROXY ? "RFC3820 Proxy" : "Unknown", i, depth);
*/
                goto failure;
            }

            if (curr_cert_type == CA) {
                /* Expected next certificate type is: CA or EEC certificate */
                expe_cert_type = CA|EEC;

                /* Exceeded CA Path Length ? */
                if (ca_path_len_countdown == 0) {
                    /* Error(oper, "CA Path Length Constraint exceeded on depth %d for certificate \"%s\". No CA certifcates were expected at this stage.\n", i, cert_subjectdn); */
                    goto failure;
                }

                /* Store pathlen, override when small, otherwise keep the smallest */
                if (cert->ex_pathlen != -1) {
                    /* Update when ca_path_len_countdown is the initial value
                     * or when the PathLenConstraint is smaller then the
                     * remembered ca_path_len_countdown */
                    if ((ca_path_len_countdown == -1) || (cert->ex_pathlen < ca_path_len_countdown)) {
                        ca_path_len_countdown = cert->ex_pathlen;
                    } else {
                        /* If a path length was already issuesd, lower ca_path_len_countdown */
                        if (ca_path_len_countdown != -1)
                            ca_path_len_countdown--;
                    }
                } else {
                    /* If a path length was already issuesd, lower ca_path_len_countdown */
                    if (ca_path_len_countdown != -1)
                        ca_path_len_countdown--;
                }

            } else if (curr_cert_type == EEC) {
                /* Expected next certificate type is: GT2_PROXY or RFC_PROXY certificate */
                expe_cert_type = GT2_PROXY|RFC_PROXY;

            } else if (curr_cert_type == GT2_PROXY) {
                /* Expected next certificate type is: GT2_PROXY certificate */
                expe_cert_type = GT2_PROXY;

            } else if (curr_cert_type == RFC_PROXY) {
                /* Expected next certificate type is: RFC_PROXY certificate */
                expe_cert_type = RFC_PROXY;

                /* Exceeded CA Path Length ? */
                if (proxy_path_len_countdown == 0) {
                    /* Error(oper, "Proxy Path Length Constraint exceeded on depth %d of %d for certificate \"%s\". No Proxy certifcates were expected at this stage.\n", i, depth, cert_subjectdn); */
                    goto failure;
                }

                /* Store pathlen, override when small, otherwise keep the smallest */
                if (cert->ex_pcpathlen != -1) {
                    /* Update when proxy_path_len_countdown is the initial value
                     * or when the PathLenConstraint is smaller then the
                     * remembered proxy_path_len_countdown */

                    if ((proxy_path_len_countdown == -1) || (cert->ex_pcpathlen < proxy_path_len_countdown)) {
                        proxy_path_len_countdown = cert->ex_pcpathlen;
                        /* Log (L_DEBUG, "\tCert here is: %s -> Setting proxy path len constraint to: %d\n", cert_subjectdn, cert->ex_pcpathlen); */
                    } else {
                        /* If a path length was already issuesd, lower ca_path_len_countdown */
                        if (proxy_path_len_countdown != -1)
                            proxy_path_len_countdown--;

                        /* Log (L_DEBUG, "\tCert here is: %s -> Countdown is at %d\n", cert_subjectdn, proxy_path_len_countdown); */
                    }
                } else {
                    /* If a path length was already issuesd, lower ca_path_len_countdown */
                    if (proxy_path_len_countdown != -1)
                        proxy_path_len_countdown--;

                    /* Log (L_DEBUG, "\tCert here is: %s -> Countdown is at %d\n", cert_subjectdn, proxy_path_len_countdown); */
                }
            }

            /* Free memory during each cycle */
            if (cert_subjectdn)
                free(cert_subjectdn);
        }
    }
/* success: */
    /* Return an OK (thumbs up) in the grid_X509_verify_callback() */
    return 1;

failure:
    if (cert_subjectdn)
        free(cert_subjectdn);
    return 0;
}


/******************************************************************************
Function:   verify_callback
Description:
    Callback function for OpenSSL to put the errors
Parameters:
    ok, X509_STORE_CTX
Returns:
******************************************************************************/
static int
grid_X509_verify_callback(int ok, X509_STORE_CTX *ctx)
{
    unsigned long   errnum   = X509_STORE_CTX_get_error(ctx);
    int             errdepth = X509_STORE_CTX_get_error_depth(ctx);
    STACK_OF(X509) *certstack;

    FILE * f = fopen("/tmp/nginx.log", "a");;
    fprintf (f, "%s / depth: %d, error depth: %d, error code: %d\n", __func__, sk_X509_num (X509_STORE_CTX_get_chain(ctx)), errdepth, (int)errnum);
    fflush(f);

    fprintf (f, "%s / subject DN here is: %s\n", __func__, X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)), NULL, 0));
    fflush(f);

    /* When not ok... */
    if (ok != 1) {
        if (errnum == X509_V_ERR_INVALID_CA) ok=1;
        if (errnum == X509_V_ERR_UNABLE_TO_GET_CRL) ok=1;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        /* I don't want to do this, really, but I have yet to figure out
           how to get openssl 0.9.8 to accept old-style proxy certificates...
        */
        if (errnum == X509_V_ERR_INVALID_PURPOSE) ok=1;
#endif
        if (errnum == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) {
            errnum = grid_X509_knownCriticalExts(X509_STORE_CTX_get_current_cert(ctx));
            ctx->error = errnum;
            if (errnum == X509_V_OK) ok=1;
        }

        /* Path length exceeded for the CA (should never happen in OpenSSL - famous last words) */
        if (ctx->error == X509_V_ERR_PATH_LENGTH_EXCEEDED) {
            /* Log( L_DEBUG, "Shallow Error X509_V_ERR_PATH_LENGTH_EXCEEDED: Running alternative RFC5280 and RFC3820 compliance tests.\n"); */
            ok = grid_verifyPathLenConstraints(X509_STORE_CTX_get_chain(ctx));
            /* Log( L_DEBUG, "Alternative RFC5280 and RFC3820 compliance tests result is: \"%s\".\n", ok == 1 ? "OK" : "Not OK"); */
        }

        /* Path length exceeded for the Proxy! -> Override and continue */
        /* This is NOT about X509_V_ERR_PATH_LENGTH_EXCEEDED */
#if OPENSSL_VERSION_NUMBER < 0x00908000L
        if (ctx->error == X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED) {
            /* Log( L_DEBUG, "Shallow Error X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: Running alternative RFC5280 and RFC3820 compliance tests.\n"); */
            ok = grid_verifyPathLenConstraints(X509_STORE_CTX_get_chain(ctx));
            /* Log( L_DEBUG, "Alternative RFC5280 and RFC3820 compliance tests result is: \"%s\".\n", ok == 1 ? "OK" : "Not OK"); */
        }
#endif
    }

    /*
     * We've now got the last certificate - the identity being used for
     * this connection. At this point we check the whole chain for valid
     * CAs or, failing that, GSI-proxy validity using grid_verifyProxy
     */
    if ( (errdepth == 0) && (ok == 1) ) {
        certstack = (STACK_OF(X509) *) X509_STORE_CTX_get_chain( ctx );

        errnum = grid_verifyProxy( certstack );

/*
        Log( L_DEBUG, "grid_verify_callback: verifyProxy returned with error code %d: %s", 
                        errnum,
                        X509_verify_cert_error_string (errnum));
*/

        ctx->error = errnum;
        ok = (errnum == X509_V_OK);
    }

    /* Error condition is unrecoverable */
    if (ok != 1) {
        fprintf (f, "%s / Still not positivielty verified!\n", __func__);
        /* Log( L_INFO, "grid_verify_callback: error code: %d, message: \"%s\"", ctx->error, X509_verify_cert_error_string (ctx->error)); */
    }

    return ok;
}


/*
 * We change the default callback to use our wrapper and discard errors
 *  due to GSI proxy chains (ie where users certs act as CAs)
 */
static int grid_check_issued_wrapper(X509_STORE_CTX *ctx,X509 *x,X509 *issuer) {
    int ret = 0;

    /* If all is ok, move out of here */
    if ((ret = X509_check_issued(issuer, x)) == X509_V_OK)
        return 1;

    /* Non self-signed certs without signing are ok if they passed
           the other checks inside X509_check_issued. Is this enough? */
    if ((ret == X509_V_ERR_KEYUSAGE_NO_CERTSIGN) &&
        (X509_subject_name_cmp(issuer, x) != 0)) return 1;

    /* If we haven't asked for issuer errors don't set ctx */
#if OPENSSL_VERSION_NUMBER < 0x00908000L
    if (!(ctx->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#else
    if (!(ctx->param->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#endif

    ctx->error = ret;
    ctx->current_cert = x;
    ctx->current_issuer = issuer;

    return ctx->verify_cb(0, ctx);
}
#endif /* RFC_3820_AND_CLASSIC_PROXY_SUPPORT */
