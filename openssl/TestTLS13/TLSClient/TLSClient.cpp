/* copy from openssl 1.0.2 and modify for win10 vs2019 by huangwenbin */



#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
//#include <unistd.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <netdb.h>
#include <winsock2.h>
#include <process.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>


#define HOME   "./"
#define CAF    HOME "ca_cert.pem"
#define CERTF  HOME "client_cert.pem"
#define KEYF   HOME "client_key.pem"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define StartTCP() { WSADATA wsd; WSAStartup(0x0002, &wsd); }


int main(void)
{
    int err = 0;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    /* ----------------------------------------------- */
    /* SSL preliminaries. We keep the certificate and key with the context. */
    const SSL_METHOD* meth = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(meth);
    if (!ctx) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    if (SSL_CTX_load_verify_locations(ctx, CAF, 0) != 1) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
    }
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* ----------------------------------------------- */
    /* Create a socket and connect to server using normal socket calls. */
    StartTCP()
    int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);       CHK_ERR(sd, "socket");
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_port = htons(1111);
    err = connect(sd, (struct sockaddr*)&dest, sizeof(dest));    CHK_ERR(err, "connect");

    /* ----------------------------------------------- */
    /* Now we have TCP conncetion. Start SSL negotiation. */
    SSL* ssl = SSL_new(ctx);                    CHK_NULL(ssl);
    SSL_set_fd(ssl, sd);
    err = SSL_connect(ssl);                     CHK_SSL(err);

    /* Get the cipher - opt */
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));
    /* Get the version - opt */
    printf("SSL version using %s\n", SSL_get_version(ssl));

    /* Get server's certificate (note: beware of dynamic allocation) - opt */
    X509* server_cert = SSL_get_peer_certificate(ssl);                        CHK_NULL(server_cert);
    if (server_cert != NULL) {
        char* str = NULL;
        printf("Client certificate:\n");

        str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);    CHK_NULL(str);
        printf("\t subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);     CHK_NULL(str);
        printf("\t issuer: %s\n", str);
        OPENSSL_free(str);

        /* We could do all sorts of certificate verification stuff here before
           deallocating the certificate. */
        printf("\t SSL_get_verify_result: %d\n", SSL_get_verify_result(ssl));

        X509_free(server_cert);
    } 

    /* --------------------------------------------------- */
    /* DATA EXCHANGE - Send a message and receive a reply. */
    err = SSL_write(ssl, "Hello World!", strlen("Hello World!"));  CHK_SSL(err);
    char buf[4096];
    err = SSL_read(ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
    buf[err] = '\0';
    printf("Got %d chars:'%s'\n", err, buf);
    SSL_shutdown(ssl);  /* send SSL/TLS close_notify */

    /* Clean up. */
    closesocket(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
/* EOF */
