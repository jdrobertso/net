/* The native part of the net package. It does name resolution, TCP
   connections and TLS. Goose holds only a 64-bit id for each connection
   (see net.goose). A table in this file maps each id to its connection.

   Goose does all the work above the byte stream: URLs, HTTP framing and
   redirects. This file does only the work that needs the operating system.

   On Windows, Schannel supplies TLS. Thus the package needs no third-party
   code, and Schannel checks each certificate against the system store.

   On Linux and macOS, OpenSSL supplies TLS. This file loads libssl with
   dlopen at the first TLS connection. Thus a build needs no OpenSSL headers
   and no link path, and a program without TLS needs no OpenSSL at all. The
   environment variable GOOSE_NET_LIBSSL can give the path of the library.

   Threads: a lock protects the handle table, and each thread has its own
   last error. Thus each Goose worker can use its own connections. Do not
   use one connection from two threads at the same time. */

#include "goose.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  define SECURITY_WIN32
#  include <security.h>
#  define SCHANNEL_USE_BLACKLISTS
#  include <subauth.h>
#  include <schannel.h>
#  define NET_TLS 1
#  define THREAD_LOCAL __declspec(thread)
typedef SOCKET net_socket;
#  define NET_BAD_SOCKET INVALID_SOCKET
#  define net_closesocket closesocket
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#  include <poll.h>
#  include <pthread.h>
#  include <signal.h>
#  include <dlfcn.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  define NET_TLS 1
#  define THREAD_LOCAL _Thread_local
typedef int net_socket;
#  define NET_BAD_SOCKET (-1)
#  define net_closesocket close
#endif

/* These are the C shapes of the values that the extern fns in net.goose
   pass. A slice is { data, len }. A Conn is a struct with one u64. */
typedef struct { const uint8_t *data; int64_t len; } net_slice;
typedef struct { uint64_t id; } net_conn;

/* ---------------------------------------------------------------- errors */

static THREAD_LOCAL char net_err[512];

static void set_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(net_err, sizeof net_err, fmt, ap);
    va_end(ap);
}

void net_error(gs_rref out) { gs_bld_append(out, net_err, (int64_t)strlen(net_err)); }

/* Copies a slice into buf as a NUL-terminated string, for the OS calls that
   need one. Returns 0 if the slice does not fit or contains a NUL byte. */
static int to_cstr(net_slice s, char *buf, size_t cap) {
    if (s.len < 0 || (size_t)s.len >= cap) return 0;
    memcpy(buf, s.data, (size_t)s.len);
    buf[s.len] = 0;
    return memchr(buf, 0, (size_t)s.len) == NULL;
}

/* ---------------------------------------------------------------- platform */

#ifdef _WIN32
static INIT_ONCE wsa_once = INIT_ONCE_STATIC_INIT;
static int wsa_ok;
static SRWLOCK table_lock = SRWLOCK_INIT;

static BOOL CALLBACK wsa_start(PINIT_ONCE once, PVOID p, PVOID *ctx) {
    WSADATA wd;
    (void)once; (void)p; (void)ctx;
    wsa_ok = WSAStartup(MAKEWORD(2, 2), &wd) == 0;
    return TRUE;
}

static int net_startup(void) {
    InitOnceExecuteOnce(&wsa_once, wsa_start, NULL, NULL);
    if (!wsa_ok) set_error("cannot start Winsock (WSAStartup failed)");
    return wsa_ok;
}

static int sock_errno(void) { return WSAGetLastError(); }
static void lock(void) { AcquireSRWLockExclusive(&table_lock); }
static void unlock(void) { ReleaseSRWLockExclusive(&table_lock); }
#else
static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t sigpipe_once = PTHREAD_ONCE_INIT;

/* A send to a socket that the peer closed raises SIGPIPE, and by default
   SIGPIPE stops the process. OpenSSL sends with no MSG_NOSIGNAL. Thus this
   file ignores SIGPIPE, but only if the program did not set a handler. */
static void ignore_sigpipe(void) {
    struct sigaction old;
    if (sigaction(SIGPIPE, NULL, &old) == 0 && old.sa_handler == SIG_DFL) signal(SIGPIPE, SIG_IGN);
}

static int net_startup(void) { pthread_once(&sigpipe_once, ignore_sigpipe); return 1; }
static int sock_errno(void) { return errno; }
static void lock(void) { pthread_mutex_lock(&table_mutex); }
static void unlock(void) { pthread_mutex_unlock(&table_mutex); }
#endif

/* Gives a short description of a socket or resolver error code. */
static const char *err_text(int e) {
#ifdef _WIN32
    switch (e) {
    case WSAHOST_NOT_FOUND: return "the host name is not known";
    case WSATRY_AGAIN: return "the name server did not answer";
    case WSANO_DATA: return "the host name has no address";
    case WSAETIMEDOUT: return "the time limit expired";
    case WSAECONNREFUSED: return "the host refused the connection";
    case WSAECONNRESET: return "the host reset the connection";
    case WSAECONNABORTED: return "the connection stopped";
    case WSAENETUNREACH: return "the network is not reachable";
    case WSAEHOSTUNREACH: return "the host is not reachable";
    case WSAENETDOWN: return "the network is down";
    default: return "socket error";
    }
#else
    return strerror(e);
#endif
}

static void set_timeouts(net_socket s, int64_t ms) {
#ifdef _WIN32
    DWORD t = ms > 0 ? (DWORD)ms : 0;
#else
    struct timeval t;
    t.tv_sec = ms > 0 ? (time_t)(ms / 1000) : 0;
    t.tv_usec = ms > 0 ? (suseconds_t)((ms % 1000) * 1000) : 0;
#endif
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t);
}

static void set_blocking(net_socket s, int blocking) {
#ifdef _WIN32
    u_long nb = blocking ? 0 : 1;
    ioctlsocket(s, FIONBIO, &nb);
#else
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, blocking ? (fl & ~O_NONBLOCK) : (fl | O_NONBLOCK));
#endif
}

/* Connects with a time limit. The socket starts a non-blocking connect, and
   then this function waits until the socket is writable. */
static int connect_timeout(net_socket s, const struct sockaddr *a, int alen, int64_t ms) {
    int r, err = 0;
    set_blocking(s, 0);
    r = connect(s, a, alen);
    if (r != 0) {
#ifdef _WIN32
        fd_set wr, ex;
        struct timeval tv;
        int fails = 0;
        if (sock_errno() != WSAEWOULDBLOCK) return 0;
        FD_ZERO(&wr); FD_SET(s, &wr);
        FD_ZERO(&ex); FD_SET(s, &ex);
        tv.tv_sec = (long)(ms / 1000);
        tv.tv_usec = (long)((ms % 1000) * 1000);
        r = select(0, NULL, &wr, &ex, ms > 0 ? &tv : NULL);
        if (r <= 0) { if (r == 0) WSASetLastError(WSAETIMEDOUT); return 0; }
        fails = FD_ISSET(s, &ex);
        if (fails) {
            int len = sizeof err;
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
            WSASetLastError(err);
            return 0;
        }
#else
        struct pollfd pfd;
        socklen_t len = sizeof err;
        if (errno != EINPROGRESS) return 0;
        pfd.fd = s; pfd.events = POLLOUT; pfd.revents = 0;
        r = poll(&pfd, 1, ms > 0 ? (int)ms : -1);
        if (r <= 0) { if (r == 0) errno = ETIMEDOUT; return 0; }
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err) { errno = err; return 0; }
#endif
    }
    set_blocking(s, 1);
    return 1;
}

/* ---------------------------------------------------------------- TLS */

/* Each backend gives four functions with the same contract:
   - tls_open does the handshake on a connected socket.
   - tls_write sends all the bytes.
   - tls_read gives a count, or 0 at the end, or -1 for an error.
   - tls_close ends the session and frees the state. */

#if defined(_WIN32)
/* The size of one TLS record: the largest payload, plus the framing. */
#define TLS_BUF (16384 + 512)

typedef struct {
    CredHandle cred;
    CtxtHandle ctx;
    int have_cred, have_ctx;
    SecPkgContext_StreamSizes sizes;
    char host[256];
    int received;        /* the count of ciphertext bytes in incoming */
    int used;            /* the count of those bytes that the current decrypted record uses */
    int available;       /* the count of plaintext bytes that the caller did not get yet */
    char *decrypted;     /* the start of those plaintext bytes, in incoming. DecryptMessage decrypts in place. */
    char incoming[TLS_BUF];
} tls_state;

static const char *sec_name(SECURITY_STATUS s) {
    switch (s) {
    case SEC_E_UNTRUSTED_ROOT: return "the root of the certificate is not trusted";
    case SEC_E_CERT_EXPIRED: return "the certificate is expired";
    case SEC_E_WRONG_PRINCIPAL: return "the certificate does not match the host name";
    case SEC_E_ILLEGAL_MESSAGE: return "the server sent an illegal TLS message";
    case SEC_E_ALGORITHM_MISMATCH: return "the server and the client have no TLS version or cipher in common";
    case SEC_E_CERT_UNKNOWN: return "Schannel cannot check the certificate";
    case SEC_E_INTERNAL_ERROR: return "internal Schannel error";
    case SEC_E_DECRYPT_FAILURE: return "a record did not decrypt";
    default: return "Schannel error";
    }
}

static int send_all(net_socket s, const char *p, int n) {
    while (n > 0) {
        int d = send(s, p, n, 0);
        if (d <= 0) return 0;
        p += d; n -= d;
    }
    return 1;
}

/* Calls InitializeSecurityContext until the handshake is complete. This
   function does the first handshake, when no context exists yet. It also
   processes TLS 1.3 post-handshake messages, for example session tickets.
   DecryptMessage reports those messages as SEC_I_RENEGOTIATE. The function
   uses the bytes in t->incoming before it reads more bytes. */
static int tls_handshake(tls_state *t, net_socket s) {
    for (;;) {
        SecBuffer in[2], out[1];
        SecBufferDesc indesc, outdesc;
        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY |
                      ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT |
                      ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS sec;
        int first = !t->have_ctx;

        in[0].BufferType = SECBUFFER_TOKEN; in[0].pvBuffer = t->incoming; in[0].cbBuffer = (unsigned long)t->received;
        in[1].BufferType = SECBUFFER_EMPTY; in[1].pvBuffer = NULL; in[1].cbBuffer = 0;
        out[0].BufferType = SECBUFFER_TOKEN; out[0].pvBuffer = NULL; out[0].cbBuffer = 0;
        indesc.ulVersion = SECBUFFER_VERSION; indesc.cBuffers = 2; indesc.pBuffers = in;
        outdesc.ulVersion = SECBUFFER_VERSION; outdesc.cBuffers = 1; outdesc.pBuffers = out;

        sec = InitializeSecurityContextA(&t->cred, first ? NULL : &t->ctx,
                                         first ? t->host : NULL, flags, 0, 0,
                                         first ? NULL : &indesc, 0,
                                         first ? &t->ctx : NULL, &outdesc, &flags, NULL);
        if (first) t->have_ctx = 1;

        /* Send all output from Schannel to the server, whatever the status.
           TLS 1.3 returns SEC_E_OK together with a last message to send. */
        if (out[0].pvBuffer) {
            int ok = out[0].cbBuffer == 0 || send_all(s, (const char *)out[0].pvBuffer, (int)out[0].cbBuffer);
            FreeContextBuffer(out[0].pvBuffer);
            if (!ok) { set_error("the send failed during the TLS handshake"); return 0; }
        }

        if (sec != SEC_E_INCOMPLETE_MESSAGE) {
            if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer > 0) {
                memmove(t->incoming, t->incoming + (t->received - (int)in[1].cbBuffer), in[1].cbBuffer);
                t->received = (int)in[1].cbBuffer;
            } else {
                t->received = 0;
            }
        }

        if (sec == SEC_E_OK) return 1;
        if (sec == SEC_I_INCOMPLETE_CREDENTIALS) { set_error("the server asks for a client certificate"); return 0; }
        /* The buffer can already hold more of the server's messages. Process them before the next recv. */
        if (sec == SEC_I_CONTINUE_NEEDED && t->received > 0) continue;
        if (sec != SEC_I_CONTINUE_NEEDED && sec != SEC_E_INCOMPLETE_MESSAGE) {
            set_error("the TLS handshake with %s failed: %s (0x%08lx)", t->host, sec_name(sec), (unsigned long)sec);
            return 0;
        }

        if (t->received == (int)sizeof t->incoming) { set_error("a TLS handshake message is too large"); return 0; }
        {
            int r = recv(s, t->incoming + t->received, (int)sizeof t->incoming - t->received, 0);
            if (r == 0) { set_error("the server closed the connection during the TLS handshake"); return 0; }
            if (r < 0) {
                int e = sock_errno();
                set_error("the recv failed during the TLS handshake: %s (error %d)", err_text(e), e);
                return 0;
            }
            t->received += r;
        }
    }
}

static tls_state *tls_open(net_socket s, const char *host) {
    SCH_CREDENTIALS cred;
    SECURITY_STATUS sec;
    tls_state *t = (tls_state *)calloc(1, sizeof *t);
    if (!t) { set_error("out of memory"); return NULL; }
    snprintf(t->host, sizeof t->host, "%s", host);

    memset(&cred, 0, sizeof cred);
    cred.dwVersion = SCH_CREDENTIALS_VERSION;
    /* Schannel checks the certificate chain and the host name against the
       system store. The client sends no certificate. Legacy ciphers are off. */
    cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    sec = AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL,
                                    &cred, NULL, NULL, &t->cred, NULL);
    if (sec != SEC_E_OK) {
        set_error("AcquireCredentialsHandle failed (0x%08lx)", (unsigned long)sec);
        free(t);
        return NULL;
    }
    t->have_cred = 1;

    if (!tls_handshake(t, s)) goto fail;
    sec = QueryContextAttributesA(&t->ctx, SECPKG_ATTR_STREAM_SIZES, &t->sizes);
    if (sec != SEC_E_OK) { set_error("QueryContextAttributes failed (0x%08lx)", (unsigned long)sec); goto fail; }
    if (t->sizes.cbHeader + t->sizes.cbMaximumMessage + t->sizes.cbTrailer > TLS_BUF) {
        set_error("the TLS record size is not as expected"); goto fail;
    }
    return t;

fail:
    if (t->have_ctx) DeleteSecurityContext(&t->ctx);
    FreeCredentialsHandle(&t->cred);
    free(t);
    return NULL;
}

static int tls_write(tls_state *t, net_socket s, const uint8_t *p, int64_t n) {
    char rec[TLS_BUF];
    while (n > 0) {
        int use = (int)(n < (int64_t)t->sizes.cbMaximumMessage ? n : (int64_t)t->sizes.cbMaximumMessage);
        SecBuffer b[4];
        SecBufferDesc desc;
        SECURITY_STATUS sec;
        b[0].BufferType = SECBUFFER_STREAM_HEADER;  b[0].pvBuffer = rec;                              b[0].cbBuffer = t->sizes.cbHeader;
        b[1].BufferType = SECBUFFER_DATA;           b[1].pvBuffer = rec + t->sizes.cbHeader;          b[1].cbBuffer = (unsigned long)use;
        b[2].BufferType = SECBUFFER_STREAM_TRAILER; b[2].pvBuffer = rec + t->sizes.cbHeader + use;    b[2].cbBuffer = t->sizes.cbTrailer;
        b[3].BufferType = SECBUFFER_EMPTY;          b[3].pvBuffer = NULL;                             b[3].cbBuffer = 0;
        memcpy(b[1].pvBuffer, p, (size_t)use);
        desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 4; desc.pBuffers = b;
        sec = EncryptMessage(&t->ctx, 0, &desc, 0);
        if (sec != SEC_E_OK) { set_error("EncryptMessage failed (0x%08lx)", (unsigned long)sec); return 0; }
        if (!send_all(s, rec, (int)(b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer))) {
            int e = sock_errno();
            set_error("the send failed: %s (error %d)", err_text(e), e);
            return 0;
        }
        p += use; n -= use;
    }
    return 1;
}

/* Copies a maximum of cap plaintext bytes into dst. Returns the count of
   bytes, or 0 at the end of the stream, or -1 for an error. The function
   waits only when no bytes are ready. */
static int tls_read(tls_state *t, net_socket s, char *dst, int cap) {
    int got = 0;
    while (got < cap) {
        if (t->decrypted) {
            int use = cap - got < t->available ? cap - got : t->available;
            memcpy(dst + got, t->decrypted, (size_t)use);
            got += use;
            if (use == t->available) {
                /* The caller has all of this record. Remove its ciphertext from the start of the buffer. */
                memmove(t->incoming, t->incoming + t->used, (size_t)(t->received - t->used));
                t->received -= t->used;
                t->used = 0; t->available = 0; t->decrypted = NULL;
            } else {
                t->available -= use;
                t->decrypted += use;
            }
            continue;
        }
        if (t->received > 0) {
            SecBuffer b[4];
            SecBufferDesc desc;
            SECURITY_STATUS sec;
            int i;
            b[0].BufferType = SECBUFFER_DATA; b[0].pvBuffer = t->incoming; b[0].cbBuffer = (unsigned long)t->received;
            for (i = 1; i < 4; i++) { b[i].BufferType = SECBUFFER_EMPTY; b[i].pvBuffer = NULL; b[i].cbBuffer = 0; }
            desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 4; desc.pBuffers = b;
            sec = DecryptMessage(&t->ctx, &desc, 0, NULL);
            if (sec == SEC_E_OK) {
                SecBuffer *data = NULL, *extra = NULL;
                for (i = 1; i < 4; i++) {
                    if (b[i].BufferType == SECBUFFER_DATA) data = &b[i];
                    if (b[i].BufferType == SECBUFFER_EXTRA) extra = &b[i];
                }
                t->decrypted = data ? (char *)data->pvBuffer : t->incoming;
                t->available = data ? (int)data->cbBuffer : 0;
                t->used = t->received - (extra ? (int)extra->cbBuffer : 0);
                continue;
            }
            /* The server sent close_notify. */
            if (sec == SEC_I_CONTEXT_EXPIRED) { t->received = 0; return got; }
            if (sec == SEC_I_RENEGOTIATE) {
                /* This is a post-handshake message, for example a TLS 1.3
                   session ticket. Send the bytes after it to the handshake
                   function, then continue to read. */
                int n = 0;
                for (i = 1; i < 4; i++) {
                    if (b[i].BufferType == SECBUFFER_EXTRA) {
                        n = (int)b[i].cbBuffer;
                        memmove(t->incoming, b[i].pvBuffer, (size_t)n);
                    }
                }
                t->received = n;
                if (!tls_handshake(t, s)) return -1;
                continue;
            }
            if (sec != SEC_E_INCOMPLETE_MESSAGE) {
                set_error("DecryptMessage failed: %s (0x%08lx)", sec_name(sec), (unsigned long)sec);
                return -1;
            }
        }
        /* Give the caller the bytes that are ready. Do not wait for more. */
        if (got > 0) return got;
        if (t->received == (int)sizeof t->incoming) { set_error("a TLS record is too large"); return -1; }
        {
            int r = recv(s, t->incoming + t->received, (int)sizeof t->incoming - t->received, 0);
            if (r == 0) return 0;
            if (r < 0) {
                int e = sock_errno();
                set_error("the recv failed: %s (error %d)", err_text(e), e);
                return -1;
            }
            t->received += r;
        }
    }
    return got;
}

static void tls_close(tls_state *t, net_socket s) {
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer in, out;
    SecBufferDesc indesc, outdesc;
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT |
                  ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    in.BufferType = SECBUFFER_TOKEN; in.pvBuffer = &type; in.cbBuffer = sizeof type;
    indesc.ulVersion = SECBUFFER_VERSION; indesc.cBuffers = 1; indesc.pBuffers = &in;
    if (ApplyControlToken(&t->ctx, &indesc) == SEC_E_OK) {
        /* Send the close_notify alert. A failure here has no effect on the result. */
        out.BufferType = SECBUFFER_TOKEN; out.pvBuffer = NULL; out.cbBuffer = 0;
        outdesc.ulVersion = SECBUFFER_VERSION; outdesc.cBuffers = 1; outdesc.pBuffers = &out;
        InitializeSecurityContextA(&t->cred, &t->ctx, NULL, flags, 0, 0, NULL, 0, NULL, &outdesc, &flags, NULL);
        if (out.pvBuffer) {
            send_all(s, (const char *)out.pvBuffer, (int)out.cbBuffer);
            FreeContextBuffer(out.pvBuffer);
        }
    }
    DeleteSecurityContext(&t->ctx);
    FreeCredentialsHandle(&t->cred);
    free(t);
}

#else  /* OpenSSL, loaded at run time */

/* The parts of the OpenSSL API that this file uses. The values come from
   the OpenSSL 3 headers. OpenSSL 1.1 has the same values. */
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;

#define OSSL_ERROR_SSL 1
#define OSSL_ERROR_WANT_READ 2
#define OSSL_ERROR_WANT_WRITE 3
#define OSSL_ERROR_SYSCALL 5
#define OSSL_ERROR_ZERO_RETURN 6
#define OSSL_VERIFY_PEER 1
#define OSSL_TLS1_2_VERSION 0x0303
#define OSSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define OSSL_CTRL_SET_MIN_PROTO_VERSION 123
#define OSSL_TLSEXT_NAMETYPE_host_name 0
#define OSSL_OP_IGNORE_UNEXPECTED_EOF ((uint64_t)1 << 7)   /* OpenSSL 3 only */
#define OSSL_X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4
#define OSSL_X509_V_OK 0

static struct {
    const SSL_METHOD *(*TLS_client_method)(void);
    SSL_CTX *(*SSL_CTX_new)(const SSL_METHOD *);
    long (*SSL_CTX_ctrl)(SSL_CTX *, int, long, void *);
    void (*SSL_CTX_set_verify)(SSL_CTX *, int, void *);
    int (*SSL_CTX_set_default_verify_paths)(SSL_CTX *);
    uint64_t (*SSL_CTX_set_options)(SSL_CTX *, uint64_t);
    SSL *(*SSL_new)(SSL_CTX *);
    int (*SSL_set_fd)(SSL *, int);
    long (*SSL_ctrl)(SSL *, int, long, void *);
    int (*SSL_set1_host)(SSL *, const char *);
    X509_VERIFY_PARAM *(*SSL_get0_param)(SSL *);
    void (*X509_VERIFY_PARAM_set_hostflags)(X509_VERIFY_PARAM *, unsigned int);
    int (*X509_VERIFY_PARAM_set1_ip_asc)(X509_VERIFY_PARAM *, const char *);
    int (*SSL_connect)(SSL *);
    int (*SSL_read)(SSL *, void *, int);
    int (*SSL_write)(SSL *, const void *, int);
    int (*SSL_get_error)(const SSL *, int);
    long (*SSL_get_verify_result)(const SSL *);
    int (*SSL_shutdown)(SSL *);
    void (*SSL_free)(SSL *);
    unsigned long (*ERR_get_error)(void);
    void (*ERR_error_string_n)(unsigned long, char *, size_t);
    void (*ERR_clear_error)(void);
    const char *(*X509_verify_cert_error_string)(long);
    unsigned long (*OpenSSL_version_num)(void);
} ossl;

static pthread_once_t ossl_once = PTHREAD_ONCE_INIT;
static SSL_CTX *ossl_ctx;
static char ossl_problem[256];

/* The places to look for libssl, in sequence. On macOS, the file never
   loads /usr/lib/libssl.dylib: that is the LibreSSL of the system, which
   stops a process that loads it in this way. */
static const char *const ossl_names[] = {
#ifdef __APPLE__
    "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
    "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
    "/opt/local/lib/libssl.3.dylib",
    "libssl.3.dylib",
#else
    "libssl.so.3",
    "libssl.so",
    "libssl.so.1.1",
#endif
    NULL
};

static void ossl_load(void) {
    void *lib = NULL;
    const char *override = getenv("GOOSE_NET_LIBSSL");
    int i;
    if (override && override[0]) lib = dlopen(override, RTLD_NOW | RTLD_LOCAL);
    for (i = 0; !lib && ossl_names[i]; i++) lib = dlopen(ossl_names[i], RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        snprintf(ossl_problem, sizeof ossl_problem,
                 "TLS needs OpenSSL 3 or 1.1, and this system has no libssl (set GOOSE_NET_LIBSSL to its path)");
        return;
    }
#define OSSL_SYM(name) \
    if (!(*(void **)&ossl.name = dlsym(lib, #name))) { \
        snprintf(ossl_problem, sizeof ossl_problem, "the libssl of this system has no %s", #name); \
        return; \
    }
    OSSL_SYM(TLS_client_method) OSSL_SYM(SSL_CTX_new) OSSL_SYM(SSL_CTX_ctrl) OSSL_SYM(SSL_CTX_set_verify)
    OSSL_SYM(SSL_CTX_set_default_verify_paths) OSSL_SYM(SSL_CTX_set_options) OSSL_SYM(SSL_new)
    OSSL_SYM(SSL_set_fd) OSSL_SYM(SSL_ctrl) OSSL_SYM(SSL_set1_host) OSSL_SYM(SSL_get0_param)
    OSSL_SYM(X509_VERIFY_PARAM_set_hostflags) OSSL_SYM(X509_VERIFY_PARAM_set1_ip_asc) OSSL_SYM(SSL_connect)
    OSSL_SYM(SSL_read) OSSL_SYM(SSL_write) OSSL_SYM(SSL_get_error) OSSL_SYM(SSL_get_verify_result)
    OSSL_SYM(SSL_shutdown) OSSL_SYM(SSL_free) OSSL_SYM(ERR_get_error) OSSL_SYM(ERR_error_string_n)
    OSSL_SYM(ERR_clear_error) OSSL_SYM(X509_verify_cert_error_string) OSSL_SYM(OpenSSL_version_num)
#undef OSSL_SYM
    ossl_ctx = ossl.SSL_CTX_new(ossl.TLS_client_method());
    if (!ossl_ctx) { snprintf(ossl_problem, sizeof ossl_problem, "SSL_CTX_new failed"); return; }
    ossl.SSL_CTX_ctrl(ossl_ctx, OSSL_CTRL_SET_MIN_PROTO_VERSION, OSSL_TLS1_2_VERSION, NULL);
    ossl.SSL_CTX_set_verify(ossl_ctx, OSSL_VERIFY_PEER, NULL);
    ossl.SSL_CTX_set_default_verify_paths(ossl_ctx);
    /* Many servers close with no close_notify. Without this option,
       OpenSSL 3 calls that an error. HTTP framing finds a short body. */
    if (ossl.OpenSSL_version_num() >= 0x30000000UL) ossl.SSL_CTX_set_options(ossl_ctx, OSSL_OP_IGNORE_UNEXPECTED_EOF);
}

typedef struct { SSL *ssl; } tls_state;

static void ossl_error(const char *what) {
    char buf[256];
    unsigned long e = ossl.ERR_get_error();
    if (e) { ossl.ERR_error_string_n(e, buf, sizeof buf); set_error("%s: %s", what, buf); }
    else { int x = errno; set_error("%s: %s (error %d)", what, x ? strerror(x) : "the connection closed", x); }
}

static int is_ip_literal(const char *host) {
    unsigned char buf[16];
    return inet_pton(AF_INET, host, buf) == 1 || inet_pton(AF_INET6, host, buf) == 1;
}

static tls_state *tls_open(net_socket s, const char *host) {
    tls_state *t;
    SSL *ssl;
    X509_VERIFY_PARAM *param;
    pthread_once(&ossl_once, ossl_load);
    if (!ossl_ctx) { set_error("%s", ossl_problem); return NULL; }
    ssl = ossl.SSL_new(ossl_ctx);
    if (!ssl) { ossl_error("SSL_new failed"); return NULL; }
    ossl.SSL_set_fd(ssl, s);
    /* SNI and the name check. An IP address gets no SNI, and the check is on the address. */
    param = ossl.SSL_get0_param(ssl);
    ossl.X509_VERIFY_PARAM_set_hostflags(param, OSSL_X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (is_ip_literal(host)) {
        ossl.X509_VERIFY_PARAM_set1_ip_asc(param, host);
    } else {
        ossl.SSL_ctrl(ssl, OSSL_CTRL_SET_TLSEXT_HOSTNAME, OSSL_TLSEXT_NAMETYPE_host_name, (void *)host);
        ossl.SSL_set1_host(ssl, host);
    }
    ossl.ERR_clear_error();
    errno = 0;
    if (ossl.SSL_connect(ssl) != 1) {
        long v = ossl.SSL_get_verify_result(ssl);
        if (v != OSSL_X509_V_OK) {
            set_error("the TLS handshake with %s failed: %s", host, ossl.X509_verify_cert_error_string(v));
        } else {
            char what[320];
            snprintf(what, sizeof what, "the TLS handshake with %s failed", host);
            ossl_error(what);
        }
        ossl.SSL_free(ssl);
        return NULL;
    }
    t = (tls_state *)calloc(1, sizeof *t);
    if (!t) { ossl.SSL_free(ssl); set_error("out of memory"); return NULL; }
    t->ssl = ssl;
    return t;
}

static int tls_write(tls_state *t, net_socket s, const uint8_t *p, int64_t n) {
    (void)s;
    while (n > 0) {
        int chunk = n > (1 << 30) ? (1 << 30) : (int)n;
        int r;
        ossl.ERR_clear_error();
        errno = 0;
        r = ossl.SSL_write(t->ssl, p, chunk);
        if (r <= 0) {
            int e = ossl.SSL_get_error(t->ssl, r);
            if (e == OSSL_ERROR_WANT_WRITE || ((e == OSSL_ERROR_SYSCALL) && (errno == EAGAIN || errno == EWOULDBLOCK))) {
                set_error("the send did not complete before the time limit");
            } else {
                ossl_error("the send failed");
            }
            return 0;
        }
        p += r; n -= r;
    }
    return 1;
}

static int tls_read(tls_state *t, net_socket s, char *dst, int cap) {
    int r, e;
    (void)s;
    ossl.ERR_clear_error();
    errno = 0;
    r = ossl.SSL_read(t->ssl, dst, cap);
    if (r > 0) return r;
    e = ossl.SSL_get_error(t->ssl, r);
    if (e == OSSL_ERROR_ZERO_RETURN) return 0;
    if (e == OSSL_ERROR_WANT_READ || (e == OSSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK))) {
        set_error("no data came before the time limit");
        return -1;
    }
    /* OpenSSL 1.1 reports a close with no close_notify as SYSCALL with errno 0. */
    if (e == OSSL_ERROR_SYSCALL && errno == 0 && ossl.ERR_get_error() == 0) return 0;
    ossl_error("the recv failed");
    return -1;
}

static void tls_close(tls_state *t, net_socket s) {
    (void)s;
    ossl.SSL_shutdown(t->ssl);
    ossl.SSL_free(t->ssl);
    free(t);
}
#endif

/* ---------------------------------------------------------------- handles */

typedef struct {
    uint64_t id;
    net_socket sock;
    int64_t timeout_ms;  /* the send and recv time limit. A listener gives it to each accepted connection. */
    int listener;        /* 1 for a socket from net_listen */
#if NET_TLS
    tls_state *tls;
#endif
} conn;

#define MAX_CONNS 256
static conn *conns[MAX_CONNS];
static uint64_t next_id = 1;

/* Ids increase and the table never uses an id again. Thus a stale Conn
   finds no connection. It cannot find the connection of a different caller. */
static conn *find_conn(net_conn c) {
    conn *found = NULL;
    int i;
    if (c.id == 0) { set_error("this is not a connection"); return NULL; }
    lock();
    for (i = 0; i < MAX_CONNS; i++) {
        if (conns[i] && conns[i]->id == c.id) { found = conns[i]; break; }
    }
    unlock();
    if (!found) set_error("connection %llu is closed", (unsigned long long)c.id);
    return found;
}

static uint64_t add_conn(conn *k) {
    uint64_t id = 0;
    int i;
    lock();
    for (i = 0; i < MAX_CONNS; i++) {
        if (!conns[i]) { k->id = next_id++; conns[i] = k; id = k->id; break; }
    }
    unlock();
    if (!id) set_error("too many connections are open (the maximum is %d)", MAX_CONNS);
    return id;
}

static conn *take_conn(net_conn c) {
    conn *found = NULL;
    int i;
    lock();
    for (i = 0; i < MAX_CONNS; i++) {
        if (conns[i] && conns[i]->id == c.id) { found = conns[i]; conns[i] = NULL; break; }
    }
    unlock();
    return found;
}

/* ---------------------------------------------------------------- the API */

net_conn net_connect(net_slice host_s, int64_t port, bool tls, int64_t timeout_ms) {
    net_conn result = { 0 };
    char host[256], service[16];
    struct addrinfo hints, *res = NULL, *ai;
    net_socket s = NET_BAD_SOCKET;
    int r, last_err = 0;
    conn *k;

    if (!net_startup()) return result;
    if (!to_cstr(host_s, host, sizeof host) || host[0] == 0) { set_error("the host name is not valid"); return result; }
    if (port <= 0 || port > 65535) { set_error("port %lld is not valid", (long long)port); return result; }
#if !NET_TLS
    if (tls) { set_error("TLS is not available on this platform"); return result; }
#endif
    snprintf(service, sizeof service, "%d", (int)port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    r = getaddrinfo(host, service, &hints, &res);
    if (r != 0) {
#ifdef _WIN32
        set_error("cannot find the address of %s: %s (error %d)", host, err_text(r), r);
#else
        set_error("cannot find the address of %s: %s", host, gai_strerror(r));
#endif
        return result;
    }
    /* Try each address in the sequence that the resolver gives. */
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == NET_BAD_SOCKET) { last_err = sock_errno(); continue; }
        if (connect_timeout(s, ai->ai_addr, (int)ai->ai_addrlen, timeout_ms)) break;
        last_err = sock_errno();
        net_closesocket(s);
        s = NET_BAD_SOCKET;
    }
    freeaddrinfo(res);
    if (s == NET_BAD_SOCKET) {
        set_error("cannot connect to %s:%d: %s (error %d)", host, (int)port, err_text(last_err), last_err);
        return result;
    }
    set_timeouts(s, timeout_ms);

    k = (conn *)calloc(1, sizeof *k);
    if (!k) { net_closesocket(s); set_error("out of memory"); return result; }
    k->sock = s;
    k->timeout_ms = timeout_ms;
#if NET_TLS
    if (tls) {
        k->tls = tls_open(s, host);
        if (!k->tls) { net_closesocket(s); free(k); return result; }
    }
#endif
    result.id = add_conn(k);
    if (!result.id) {
#if NET_TLS
        if (k->tls) tls_close(k->tls, s);
#endif
        net_closesocket(s);
        free(k);
    }
    return result;
}

bool net_send(net_conn c, net_slice data) {
    conn *k = find_conn(c);
    if (!k) return false;
#if NET_TLS
    if (k->tls) return tls_write(k->tls, k->sock, data.data, data.len) != 0;
#endif
    {
        const char *p = (const char *)data.data;
        int64_t n = data.len;
        while (n > 0) {
            int chunk = n > (1 << 30) ? (1 << 30) : (int)n;
#ifdef MSG_NOSIGNAL
            int d = (int)send(k->sock, p, chunk, MSG_NOSIGNAL);
#else
            int d = (int)send(k->sock, p, chunk, 0);
#endif
            if (d <= 0) {
                int e = sock_errno();
                set_error("the send failed: %s (error %d)", err_text(e), e);
                return false;
            }
            p += d; n -= d;
        }
    }
    return true;
}

int64_t net_recv(net_conn c, gs_rref out, int64_t max) {
    char buf[16384];
    int cap = max <= 0 || max > (int64_t)sizeof buf ? (int)sizeof buf : (int)max;
    int r;
    conn *k = find_conn(c);
    if (!k) return -1;
#if NET_TLS
    if (k->tls) {
        r = tls_read(k->tls, k->sock, buf, cap);
    } else
#endif
    {
        r = (int)recv(k->sock, buf, cap, 0);
        if (r < 0) {
            int e = sock_errno();
#ifdef _WIN32
            if (e == WSAETIMEDOUT) set_error("no data came before the time limit"); else
#else
            if (e == EAGAIN || e == EWOULDBLOCK) set_error("no data came before the time limit"); else
#endif
            set_error("the recv failed: %s (error %d)", err_text(e), e);
            r = -1;
        }
    }
    if (r > 0) gs_bld_append(out, buf, r);
    return r;
}

bool net_set_timeout(net_conn c, int64_t ms) {
    conn *k = find_conn(c);
    if (!k) return false;
    k->timeout_ms = ms;
    if (!k->listener) set_timeouts(k->sock, ms);
    return true;
}

/* Starts TLS on a connection that is already open, for example a tunnel
   through a proxy. */
bool net_start_tls(net_conn c, net_slice host_s) {
    char host[256];
    conn *k = find_conn(c);
    if (!k) return false;
    if (!to_cstr(host_s, host, sizeof host) || host[0] == 0) { set_error("the host name is not valid"); return false; }
#if NET_TLS
    if (k->tls) { set_error("the connection already uses TLS"); return false; }
    k->tls = tls_open(k->sock, host);
    return k->tls != NULL;
#else
    set_error("TLS is not available on this platform");
    return false;
#endif
}

/* Opens a socket that waits for connections on host:port. An empty host
   means all local addresses. Port 0 lets the system select a free port.
   net_local_port gives that port. */
net_conn net_listen(net_slice host_s, int64_t port, int64_t backlog) {
    net_conn result = { 0 };
    char host[256], service[16];
    struct addrinfo hints, *res = NULL, *ai;
    net_socket s = NET_BAD_SOCKET;
    int r, last_err = 0;
    conn *k;

    if (!net_startup()) return result;
    if (!to_cstr(host_s, host, sizeof host)) { set_error("the host name is not valid"); return result; }
    if (port < 0 || port > 65535) { set_error("port %lld is not valid", (long long)port); return result; }
    snprintf(service, sizeof service, "%d", (int)port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    r = getaddrinfo(host[0] ? host : NULL, service, &hints, &res);
    if (r != 0) {
#ifdef _WIN32
        set_error("cannot find the address of %s: %s (error %d)", host, err_text(r), r);
#else
        set_error("cannot find the address of %s: %s", host, gai_strerror(r));
#endif
        return result;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == NET_BAD_SOCKET) { last_err = sock_errno(); continue; }
#ifndef _WIN32
        {
            /* Lets a server start again at once on the same port. Windows has
               a different meaning for this option, so it is POSIX only. */
            int on = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        }
#endif
        if (bind(s, ai->ai_addr, (int)ai->ai_addrlen) == 0 &&
            listen(s, backlog > 0 ? (int)backlog : SOMAXCONN) == 0) break;
        last_err = sock_errno();
        net_closesocket(s);
        s = NET_BAD_SOCKET;
    }
    freeaddrinfo(res);
    if (s == NET_BAD_SOCKET) {
        set_error("cannot listen on port %d: %s (error %d)", (int)port, err_text(last_err), last_err);
        return result;
    }

    k = (conn *)calloc(1, sizeof *k);
    if (!k) { net_closesocket(s); set_error("out of memory"); return result; }
    k->sock = s;
    k->listener = 1;
    k->timeout_ms = 15000;
    result.id = add_conn(k);
    if (!result.id) { net_closesocket(s); free(k); }
    return result;
}

/* Waits for a maximum of timeout_ms for the next connection on a listener.
   Zero means no time limit. The new connection gets the time limit of the
   listener for its sends and recvs. */
net_conn net_accept(net_conn lc, int64_t timeout_ms) {
    net_conn result = { 0 };
    net_socket s;
    int r;
    conn *k, *l = find_conn(lc);
    if (!l) return result;
    if (!l->listener) { set_error("the connection is not a listener"); return result; }
#ifdef _WIN32
    {
        fd_set rd;
        struct timeval tv;
        FD_ZERO(&rd); FD_SET(l->sock, &rd);
        tv.tv_sec = (long)(timeout_ms / 1000);
        tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
        r = select(0, &rd, NULL, NULL, timeout_ms > 0 ? &tv : NULL);
    }
#else
    {
        struct pollfd pfd;
        pfd.fd = l->sock; pfd.events = POLLIN; pfd.revents = 0;
        r = poll(&pfd, 1, timeout_ms > 0 ? (int)timeout_ms : -1);
    }
#endif
    if (r == 0) { set_error("no connection came before the time limit"); return result; }
    if (r < 0) { int e = sock_errno(); set_error("the wait for a connection failed: %s (error %d)", err_text(e), e); return result; }
    s = accept(l->sock, NULL, NULL);
    if (s == NET_BAD_SOCKET) { int e = sock_errno(); set_error("accept failed: %s (error %d)", err_text(e), e); return result; }
    set_timeouts(s, l->timeout_ms);

    k = (conn *)calloc(1, sizeof *k);
    if (!k) { net_closesocket(s); set_error("out of memory"); return result; }
    k->sock = s;
    k->timeout_ms = l->timeout_ms;
    result.id = add_conn(k);
    if (!result.id) { net_closesocket(s); free(k); }
    return result;
}

/* Writes the text form of a socket address and returns its port, or -1. */
static int64_t format_addr(const struct sockaddr_storage *a, gs_rref *out) {
    char text[INET6_ADDRSTRLEN];
    const void *p;
    int port;
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        p = &a6->sin6_addr; port = ntohs(a6->sin6_port);
    } else if (a->ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        p = &a4->sin_addr; port = ntohs(a4->sin_port);
    } else {
        set_error("the address family is not known");
        return -1;
    }
    if (out && inet_ntop(a->ss_family, p, text, sizeof text)) gs_bld_append(*out, text, (int64_t)strlen(text));
    return port;
}

/* Returns the local port of a connection or a listener, or -1. */
int64_t net_local_port(net_conn c) {
    struct sockaddr_storage a;
    socklen_t len = sizeof a;
    conn *k = find_conn(c);
    if (!k) return -1;
    if (getsockname(k->sock, (struct sockaddr *)&a, &len) != 0) {
        int e = sock_errno();
        set_error("getsockname failed: %s (error %d)", err_text(e), e);
        return -1;
    }
    return format_addr(&a, NULL);
}

/* Appends the address of the peer and returns its port, or -1. */
int64_t net_peer(net_conn c, gs_rref out) {
    struct sockaddr_storage a;
    socklen_t len = sizeof a;
    conn *k = find_conn(c);
    if (!k) return -1;
    if (getpeername(k->sock, (struct sockaddr *)&a, &len) != 0) {
        int e = sock_errno();
        set_error("getpeername failed: %s (error %d)", err_text(e), e);
        return -1;
    }
    return format_addr(&a, &out);
}

void net_close(net_conn c) {
    conn *k = take_conn(c);
    if (!k) return;
#if NET_TLS
    if (k->tls) tls_close(k->tls, k->sock);
#endif
    net_closesocket(k->sock);
    free(k);
}

bool net_resolve(net_slice host_s, gs_rref out) {
    char host[256], text[INET6_ADDRSTRLEN];
    struct addrinfo hints, *res = NULL, *ai;
    int r;
    if (!net_startup()) return false;
    if (!to_cstr(host_s, host, sizeof host) || host[0] == 0) { set_error("the host name is not valid"); return false; }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    r = getaddrinfo(host, NULL, &hints, &res);
    if (r != 0) {
#ifdef _WIN32
        set_error("cannot find the address of %s: %s (error %d)", host, err_text(r), r);
#else
        set_error("cannot find the address of %s: %s", host, gai_strerror(r));
#endif
        return false;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        const void *a = ai->ai_family == AF_INET6
            ? (const void *)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr
            : (const void *)&((struct sockaddr_in *)ai->ai_addr)->sin_addr;
        if (inet_ntop(ai->ai_family, a, text, sizeof text)) {
            gs_bld_append(out, text, (int64_t)strlen(text));
            gs_bld_append(out, "\n", 1);
        }
    }
    freeaddrinfo(res);
    return true;
}
