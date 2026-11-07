// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define LISTEN_PORT 18443
#define SERVER_CERT "/usr/local/etc/refineid/ca/server.crt"
#define SERVER_KEY  "/usr/local/etc/refineid/ca/server.key"

static SSL_CTX *g_server_ssl_ctx = NULL;
static SSL_CTX *g_client_ssl_ctx = NULL;
static pthread_mutex_t g_client_ctx_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_client_ctx_initialized = 0;

static int pin_reader(UI *ui, UI_STRING *uis) {
    if (UI_get_string_type(uis) == UIT_PROMPT || UI_get_string_type(uis) == UIT_VERIFY) {
        const char *env_pin = getenv("REFINEID_PIN");
        if (env_pin && strlen(env_pin) > 0) {
            UI_set_result(ui, uis, env_pin);
            return 1;
        }

        fprintf(stderr, "[proxy] Prompting for PIN via refineid-ask-pin...\n");
        FILE *fp = popen("env DISPLAY=:0 XAUTHORITY=/home/pk/.Xauthority XDG_RUNTIME_DIR=/var/run/xdg/pk /usr/local/bin/refineid-ask-pin 'RefineID Smart Card: Enter PIN 1 (Authentication):'", "r");
        if (fp) {
            char buf[64] = {0};
            if (fgets(buf, sizeof(buf), fp)) {
                buf[strcspn(buf, "\r\n")] = 0;
                UI_set_result(ui, uis, buf);
                OPENSSL_cleanse(buf, sizeof(buf));
                pclose(fp);
                return 1;
            }
            pclose(fp);
        }
    }
    return 1;
}

static int init_client_ssl_ctx_locked() {
    if (g_client_ctx_initialized && g_client_ssl_ctx) return 1;

    UI_METHOD *ui_method = UI_create_method("pin_ui");
    UI_method_set_reader(ui_method, pin_reader);
    UI_set_default_method(ui_method);

    const char *cert_uri = "pkcs11:token=Basic%20%28PIN%201%29;type=cert";
    const char *key_uri  = "pkcs11:token=Basic%20%28PIN%201%29;type=private";

    fprintf(stderr, "[proxy] Loading client cert from PKCS#11...\n");
    OSSL_STORE_CTX *sctx = OSSL_STORE_open(cert_uri, ui_method, NULL, NULL, NULL);
    if (!sctx) {
        fprintf(stderr, "[proxy] Failed to open cert store URI\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    X509 *cert = NULL;
    X509 *ca_cert = NULL;
    while (!OSSL_STORE_eof(sctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
        if (!info) continue;
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT) {
            X509 *x = OSSL_STORE_INFO_get1_CERT(info);
            if (!X509_check_ca(x) && !cert) {
                cert = x;
            } else if (X509_check_ca(x) && !ca_cert) {
                ca_cert = x;
            } else {
                X509_free(x);
            }
        }
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(sctx);
    if (!cert) {
        fprintf(stderr, "[proxy] Client certificate not found\n");
        if (ca_cert) X509_free(ca_cert);
        return 0;
    }

    char sname[256];
    X509_NAME_oneline(X509_get_subject_name(cert), sname, sizeof(sname));
    fprintf(stderr, "[proxy] Loaded client certificate: %s\n", sname);

    fprintf(stderr, "[proxy] Loading private key from PKCS#11...\n");
    OSSL_STORE_CTX *kctx = OSSL_STORE_open(key_uri, ui_method, NULL, NULL, NULL);
    if (!kctx) {
        fprintf(stderr, "[proxy] Failed to open key store URI\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        if (ca_cert) X509_free(ca_cert);
        return 0;
    }
    EVP_PKEY *pkey = NULL;
    while (!OSSL_STORE_eof(kctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(kctx);
        if (!info) continue;
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(kctx);

    if (!pkey) {
        fprintf(stderr, "[proxy] Client private key not found\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        if (ca_cert) X509_free(ca_cert);
        return 0;
    }

    g_client_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_client_ssl_ctx) {
        X509_free(cert);
        if (ca_cert) X509_free(ca_cert);
        EVP_PKEY_free(pkey);
        return 0;
    }
    SSL_CTX_set_default_verify_paths(g_client_ssl_ctx);

    SSL_CTX_use_certificate(g_client_ssl_ctx, cert);
    if (ca_cert) {
        SSL_CTX_add_extra_chain_cert(g_client_ssl_ctx, ca_cert);
    }
    SSL_CTX_use_PrivateKey(g_client_ssl_ctx, pkey);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    g_client_ctx_initialized = 1;
    fprintf(stderr, "[proxy] Client SSL context successfully initialized!\n");
    return 1;
}

static int should_intercept(const char *host) {
    if (strstr(host, "card.refineid.fi")) return 1;
    if (strstr(host, "suomi.fi")) return 1;
    if (strstr(host, "fineid.fi")) return 1;
    if (strstr(host, "dvv.fi")) return 1;
    if (strstr(host, "vrk.fi")) return 1;
    return 0;
}

static int connect_tcp(const char *host, int port) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    int sock = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
        if (sock == -1) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

static void relay_raw(int cfd, int sfd) {
    struct pollfd fds[2];
    fds[0].fd = cfd;
    fds[0].events = POLLIN;
    fds[1].fd = sfd;
    fds[1].events = POLLIN;

    char buf[16384];
    while (1) {
        int ret = poll(fds, 2, 60000);
        if (ret <= 0) break;

        if (fds[0].revents & POLLIN) {
            ssize_t n = read(cfd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(sfd, buf, n) <= 0) break;
        }
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(sfd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(cfd, buf, n) <= 0) break;
        }
        if ((fds[0].revents & (POLLERR | POLLHUP)) || (fds[1].revents & (POLLERR | POLLHUP))) {
            break;
        }
    }
}

static void relay_ssl(SSL *cssl, SSL *sssl) {
    int cfd = SSL_get_fd(cssl);
    int sfd = SSL_get_fd(sssl);

    struct pollfd fds[2];
    fds[0].fd = cfd;
    fds[0].events = POLLIN;
    fds[1].fd = sfd;
    fds[1].events = POLLIN;

    char buf[16384];
    while (1) {
        while (SSL_pending(cssl) > 0) {
            int n = SSL_read(cssl, buf, sizeof(buf));
            if (n <= 0) return;
            if (SSL_write(sssl, buf, n) <= 0) return;
        }
        while (SSL_pending(sssl) > 0) {
            int n = SSL_read(sssl, buf, sizeof(buf));
            if (n <= 0) return;
            if (SSL_write(cssl, buf, n) <= 0) return;
        }

        int ret = poll(fds, 2, 60000);
        if (ret <= 0) break;

        if (fds[0].revents & POLLIN) {
            int n = SSL_read(cssl, buf, sizeof(buf));
            if (n <= 0) break;
            if (SSL_write(sssl, buf, n) <= 0) break;
        }
        if (fds[1].revents & POLLIN) {
            int n = SSL_read(sssl, buf, sizeof(buf));
            if (n <= 0) break;
            if (SSL_write(cssl, buf, n) <= 0) break;
        }
        if ((fds[0].revents & (POLLERR | POLLHUP)) || (fds[1].revents & (POLLERR | POLLHUP))) {
            break;
        }
    }
}

static void *client_thread(void *arg) {
    int cfd = (int)(intptr_t)arg;

    char req[4096];
    size_t req_len = 0;
    while (req_len < sizeof(req) - 1) {
        ssize_t n = read(cfd, req + req_len, 1);
        if (n <= 0) {
            close(cfd);
            return NULL;
        }
        req_len += n;
        req[req_len] = '\0';
        if (strstr(req, "\r\n\r\n") != NULL) break;
    }

    char method[16], hostport[256], proto[16];
    if (sscanf(req, "%15s %255s %15s", method, hostport, proto) < 2) {
        close(cfd);
        return NULL;
    }

    if (strcasecmp(method, "CONNECT") != 0) {
        close(cfd);
        return NULL;
    }

    char host[256] = {0};
    int port = 443;
    char *colon = strchr(hostport, ':');
    if (colon) {
        *colon = '\0';
        strncpy(host, hostport, sizeof(host) - 1);
        port = atoi(colon + 1);
    } else {
        strncpy(host, hostport, sizeof(host) - 1);
    }

    int intercept = should_intercept(host);
    fprintf(stderr, "[proxy] Request: %s %s:%d (intercept=%d)\n", method, host, port, intercept);

    int sfd = connect_tcp(host, port);
    if (sfd < 0) {
        const char *err502 = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        write(cfd, err502, strlen(err502));
        close(cfd);
        return NULL;
    }

    const char *ok200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
    write(cfd, ok200, strlen(ok200));

    if (!intercept) {
        relay_raw(cfd, sfd);
        close(sfd);
        close(cfd);
        return NULL;
    }

    pthread_mutex_lock(&g_client_ctx_lock);
    if (!init_client_ssl_ctx_locked()) {
        pthread_mutex_unlock(&g_client_ctx_lock);
        fprintf(stderr, "[proxy] Failed to initialize client SSL context for %s\n", host);
        close(sfd);
        close(cfd);
        return NULL;
    }
    pthread_mutex_unlock(&g_client_ctx_lock);

    SSL *cssl = SSL_new(g_server_ssl_ctx);
    SSL_set_fd(cssl, cfd);
    if (SSL_accept(cssl) <= 0) {
        fprintf(stderr, "[proxy] Client SSL_accept failed for %s\n", host);
        ERR_print_errors_fp(stderr);
        SSL_free(cssl);
        close(sfd);
        close(cfd);
        return NULL;
    }

    SSL *sssl = SSL_new(g_client_ssl_ctx);
    SSL_set_tlsext_host_name(sssl, host);
    SSL_set_fd(sssl, sfd);
    if (SSL_connect(sssl) <= 0) {
        fprintf(stderr, "[proxy] Upstream SSL_connect with mTLS failed for %s\n", host);
        ERR_print_errors_fp(stderr);
        SSL_free(sssl);
        SSL_shutdown(cssl);
        SSL_free(cssl);
        close(sfd);
        close(cfd);
        return NULL;
    }

    fprintf(stderr, "[proxy] === BOTH TLS HANDSHAKES SUCCESSFUL for %s! Relaying... ===\n", host);
    relay_ssl(cssl, sssl);

    SSL_shutdown(sssl);
    SSL_shutdown(cssl);
    SSL_free(sssl);
    SSL_free(cssl);
    close(sfd);
    close(cfd);
    return NULL;
}

int main() {
    if (!getenv("OPENSSL_CONF")) {
        setenv("OPENSSL_CONF", "/usr/local/etc/refineid/openssl_pkcs11.cnf", 1);
    }
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "[proxy] Failed to load OpenSSL config\n");
    }

    g_server_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (SSL_CTX_use_certificate_file(g_server_ssl_ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[proxy] Failed to load server cert\n");
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(g_server_ssl_ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[proxy] Failed to load server key\n");
        return 1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(LISTEN_PORT);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(lfd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(lfd, 64) != 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, "[proxy] RefineID mTLS Bridge listening on 127.0.0.1:%d\n", LISTEN_PORT);

    while (1) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;
        pthread_t th;
        pthread_create(&th, NULL, client_thread, (void *)(intptr_t)cfd);
        pthread_detach(th);
    }

    return 0;
}
