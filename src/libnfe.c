#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include "libnfe.h"

// Environment enum
typedef enum {
    ENV_PROD = 1,
    ENV_DEV = 2
} Environment;

// Configuration structure
typedef struct {
    char* certificate_path;
    char* certificate_pass;
    char* cacerts_path;
    char* sefaz;
    Environment environment;
} Config;

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

// Load configuration from system.cfg
static Config* load_config() {
    const char* cfg_path = "C:\\madeiras\\erp\\cfg\\system.cfg";
    FILE* file = fopen(cfg_path, "r");
    if (!file) {
        return NULL;
    }

    Config* config = (Config*)malloc(sizeof(Config));
    if (!config) {
        fclose(file);
        return NULL;
    }
    config->certificate_path = NULL;
    config->certificate_pass = NULL;
    config->cacerts_path = NULL;
    config->sefaz = NULL;
    config->environment = ENV_DEV; // Default to dev

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char* key = strtok(line, "=");
        char* value = strtok(NULL, "\n");
        if (key && value) {
            if (strcmp(key, "certificate_path") == 0) {
                config->certificate_path = _strdup(value);
            } else if (strcmp(key, "certificate_pass") == 0) {
                config->certificate_pass = _strdup(value);
            } else if (strcmp(key, "cacerts_path") == 0) {
                config->cacerts_path = _strdup(value);
            } else if (strcmp(key, "sefaz") == 0) {
                config->sefaz = _strdup(value);
            } else if (strcmp(key, "environment") == 0) {
                config->environment = atoi(value);
            }
        }
    }
    fclose(file);

    if (!config->certificate_path || !config->certificate_pass || !config->cacerts_path || !config->sefaz) {
        free(config->certificate_path);
        free(config->certificate_pass);
        free(config->cacerts_path);
        free(config->sefaz);
        free(config);
        return NULL;
    }
    return config;
}

static void free_config(Config* config) {
    if (config) {
        free(config->certificate_path);
        free(config->certificate_pass);
        free(config->cacerts_path);
        free(config->sefaz);
        free(config);
    }
}

// Load endpoint from pr-prod.cfg or pr-dev.cfg
static char* get_endpoint(const char* sefaz, Environment env, const char* operation) {
    char cfg_file[64];
    snprintf(cfg_file, sizeof(cfg_file), "C:\\madeiras\\erp\\cfg\\%s-%s.cfg", sefaz, env == ENV_PROD ? "prod" : "dev");
    FILE* file = fopen(cfg_file, "r");
    if (!file) {
        return NULL;
    }

    char* endpoint = NULL;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char* name = strtok(line, "=");
        char* url = strtok(NULL, "\n");
        if (name && url && strcmp(name, operation) == 0) {
            endpoint = _strdup(url);
            break;
        }
    }
    fclose(file);
    return endpoint;
}

// Private function to handle SOAP requests
static const char* nfe_request(const char* operation, const char* soap_payload) {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return return_error("Winsock initialization failed");
    }

    // Load configuration
    Config* config = load_config();
    if (!config) {
        WSACleanup();
        return return_error("Failed to load system.cfg");
    }

    // Initialize OpenSSL
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1) {
        free_config(config);
        WSACleanup();
        return return_error("OpenSSL initialization failed");
    }
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) != 1) {
        free_config(config);
        WSACleanup();
        return return_error("OpenSSL crypto initialization failed");
    }

    // Load OpenSSL providers
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        free_config(config);
        WSACleanup();
        return return_error("Failed to load default provider");
    }
    OSSL_PROVIDER* legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy_provider) {
        OSSL_PROVIDER_unload(default_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to load legacy provider");
    }

    // Create SSL context
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to create SSL context");
    }

    // Load client certificate
    BIO* pfx_file = BIO_new_file(config->certificate_path, "rb");
    if (!pfx_file) {
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to open PFX file");
    }

    PKCS12* pfx = d2i_PKCS12_bio(pfx_file, NULL);
    if (!pfx) {
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to load PFX");
    }

    X509* cert = NULL;
    EVP_PKEY* key = NULL;
    if (PKCS12_parse(pfx, config->certificate_pass, &key, &cert, NULL) != 1) {
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
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
        free_config(config);
        WSACleanup();
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
        free_config(config);
        WSACleanup();
        return return_error("Failed to use private key");
    }

    if (SSL_CTX_load_verify_locations(ssl_ctx, config->cacerts_path, NULL) != 1) {
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to load CA certs");
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    // Load endpoint
    char* endpoint = get_endpoint(config->sefaz, config->environment, operation);
    if (!endpoint) {
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to load endpoint");
    }

    char host[256];
    char path[256];
    if (sscanf(endpoint, "https://%[^/]/%s", host, path) != 2) {
        free(endpoint);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to parse endpoint URL");
    }
    // Append port if not specified
    if (strstr(host, ":") == NULL) {
        strcat(host, ":443");
    }

    BIO* bio = BIO_new_ssl_connect(ssl_ctx);
    if (!bio) {
        free(endpoint);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to create BIO");
    }

    SSL* ssl = NULL;
    if (BIO_get_ssl(bio, &ssl) != 1 || ssl == NULL) {
        free(endpoint);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("BIO_get_ssl failed");
    }

    if (BIO_set_conn_hostname(bio, host) != 1) {
        free(endpoint);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to set hostname");
    }

    if (BIO_do_connect(bio) != 1) {
        char err_buf[256];
        unsigned long err = ERR_get_error();
        ERR_error_string(err, err_buf);
        int sys_err = WSAGetLastError();
        snprintf(response_buffer, sizeof(response_buffer), "Connection failed: %s (Winsock error: %d)", err_buf, sys_err);
        free(endpoint);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return response_buffer;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        char err_buf[256];
        ERR_error_string(ERR_get_error(), err_buf);
        snprintf(response_buffer, sizeof(response_buffer), "TLS verification failed: %s", err_buf);
        free(endpoint);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return response_buffer;
    }

    char* request = (char*)malloc(strlen(soap_payload) + 256);
    if (!request) {
        free(endpoint);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to allocate request");
    }
    sprintf(request,
        "POST /%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/soap+xml; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", path, host, strlen(soap_payload), soap_payload);
    free(endpoint);

    if (BIO_write(bio, request, (int)strlen(request)) <= 0) {
        char err_buf[256];
        ERR_error_string(ERR_get_error(), err_buf);
        snprintf(response_buffer, sizeof(response_buffer), "Write failed: %s", err_buf);
        free(request);
        BIO_free_all(bio);
        X509_free(cert);
        EVP_PKEY_free(key);
        PKCS12_free(pfx);
        BIO_free(pfx_file);
        SSL_CTX_free(ssl_ctx);
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return response_buffer;
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
                free_config(config);
                WSACleanup();
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
            char err_buf[256];
            ERR_error_string(ERR_get_error(), err_buf);
            snprintf(response_buffer, sizeof(response_buffer), "Read failed: %s", err_buf);
            free(response);
            BIO_free_all(bio);
            X509_free(cert);
            EVP_PKEY_free(key);
            PKCS12_free(pfx);
            BIO_free(pfx_file);
            SSL_CTX_free(ssl_ctx);
            OSSL_PROVIDER_unload(default_provider);
            OSSL_PROVIDER_unload(legacy_provider);
            free_config(config);
            WSACleanup();
            return response_buffer;
        }
    }

    const char* xml_start = strstr(response, "<?xml");
    if (!xml_start) xml_start = response;

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
        free_config(config);
        WSACleanup();
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
    free_config(config);
    WSACleanup();

    return response_buffer;
}

__declspec(dllexport) const char* status_servico(const char* soap_payload) {
    return nfe_request("NfeStatusServico", soap_payload);
}