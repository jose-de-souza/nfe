#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include "libnfe.h"

// Static buffer for response and error messages
static char response_buffer[4096] = {0};

static const char* return_error(const char* msg) {
    size_t msg_len = strlen(msg);
    if (msg_len >= sizeof(response_buffer)) {
        return NULL; // Error message too large
    }
    strncpy(response_buffer, msg, sizeof(response_buffer) - 1);
    response_buffer[sizeof(response_buffer) - 1] = '\0';
    return response_buffer;
}

__declspec(dllexport) const char* status_servico(void) {
    // Initialize OpenSSL
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1) {
        return return_error("OpenSSL initialization failed");
    }
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) != 1) {
        return return_error("OpenSSL crypto initialization failed");
    }

    // Load default provider
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        return return_error("Failed to load default provider");
    }

    // Load legacy provider
    OSSL_PROVIDER* legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy_provider) {
        OSSL_PROVIDER_unload(default_provider);
        return return_error("Failed to load legacy provider");
    }

    // Create SSL context
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to create SSL context");
    }

    // Load client certificate from .pfx file
    const char* pfx_path = "C:/madeiras/erp/certificates/client.pfx";
    BIO* pfx_file = BIO_new_file(pfx_path, "rb");
    if (!pfx_file) {
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to open PFX file");
    }

    PKCS12* pfx = d2i_PKCS12_bio(pfx_file, NULL);
    if (!pfx) {
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to load PFX");
    }

    X509* cert = NULL;
    EVP_PKEY* key = NULL;
    if (PKCS12_parse(pfx, "123", &key, &cert, NULL) != 1) {
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to parse PFX");
    }

    if (SSL_CTX_use_certificate(ssl_ctx, cert) != 1) {
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to use certificate");
    }

    if (SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1) {
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to use private key");
    }

    // Load CA certificates
    const char* cacerts_path = "C:/madeiras/erp/certificates/cacerts.pem";
    if (SSL_CTX_load_verify_locations(ssl_ctx, cacerts_path, NULL) != 1) {
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to load CA certs");
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    // Create BIO for HTTPS connection
    const char* host = "homologacao.nfe.sefa.pr.gov.br:443";
    BIO* bio = BIO_new_ssl_connect(ssl_ctx);
    if (!bio) {
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to create BIO");
    }

    SSL* ssl = NULL;
    if (BIO_get_ssl(bio, &ssl) != 1 || ssl == NULL) {
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("BIO_get_ssl failed");
    }

    if (BIO_set_conn_hostname(bio, host) != 1) {
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to set hostname");
    }

    if (BIO_do_connect(bio) != 1) {
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Connection failed");
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("TLS verification failed");
    }

    const char* status_servico_request =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\">"
        "<soap:Header>"
        "<nfeCabecMsg>"
        "<cUF>41</cUF>"
        "<versaoDados>4.00</versaoDados>"
        "</nfeCabecMsg>"
        "</soap:Header>"
        "<soap:Body>"
        "<nfeDadosMsg>"
        "<consStatServ versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\">"
        "<tpAmb>2</tpAmb>"
        "<cUF>41</cUF>"
        "<xServ>STATUS</xServ>"
        "</consStatServ>"
        "</nfeDadosMsg>"
        "</soap:Body>"
        "</soap:Envelope>";

    char* request = (char*)malloc(strlen(status_servico_request) + 256);
    if (!request) {
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Failed to allocate request");
    }
    sprintf(request,
        "POST /nfe/NFeStatusServico4 HTTP/1.1\r\n"
        "Host: homologacao.nfe.sefa.pr.gov.br\r\n"
        "Content-Type: application/soap+xml; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", strlen(status_servico_request), status_servico_request);

    if (strlen(request) > INT_MAX) {
        free(request);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Request length exceeds maximum");
    }

    if (BIO_write(bio, request, (int)strlen(request)) <= 0) {
        free(request);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Write failed");
    }
    free(request);

    char* response = NULL;
    size_t response_size = 0;
    char buf[4096];
    while (1) {
        int read = BIO_read(bio, buf, sizeof(buf));
        if (read > 0) {
            char* new_response = (char*)realloc(response, response_size + read + 1);
            if (!new_response) {
                free(response);
                BIO_free_all(bio);
                X509_free(cert);
                EVP_PKEY_free(key);
                PKCS12_free(pfx);
                BIO_free(pfx_file);
                SSL_CTX_free(ssl_ctx);
                OSSL_PROVIDER_unload(default_provider);
                OSSL_PROVIDER_unload(legacy_provider);
                return return_error("Failed to append response");
            }
            response = new_response;
            memcpy(response + response_size, buf, read);
            response_size += read;
            response[response_size] = '\0';
        } else if (read == 0) {
            break;
        } else if (BIO_should_retry(bio)) {
            continue;
        } else {
            free(response);
            BIO_free_all(bio);
            X509_free(cert);
            EVP_PKEY_free(key);
            PKCS12_free(pfx);
            BIO_free(pfx_file);
            SSL_CTX_free(ssl_ctx);
            OSSL_PROVIDER_unload(default_provider);
            OSSL_PROVIDER_unload(legacy_provider);
            return return_error("Read failed");
        }
    }

    // Find XML start
    const char* xml_start = strstr(response, "<?xml");
    if (!xml_start) xml_start = response;

    // Copy to static buffer
    if (strlen(xml_start) >= sizeof(response_buffer)) {
        free(response);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        return return_error("Response too large for static buffer");
    }

    strncpy(response_buffer, xml_start, sizeof(response_buffer) - 1);
    response_buffer[sizeof(response_buffer) - 1] = '\0';

    free(response);
    BIO_free_all(bio);
    X509_free(cert);
    EVP_PKEY_free(key);
    PKCS12_free(pfx);
    BIO_free(pfx_file);
    SSL_CTX_free(ssl_ctx);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_PROVIDER_unload(legacy_provider);

    return response_buffer;
}