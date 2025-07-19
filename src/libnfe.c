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
#include "nfe_utils.h"

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
static char response_buffer[8192] = {0};

static const char* return_error(const char* msg) {
    size_t msg_len = strlen(msg);
    if (msg_len >= sizeof(response_buffer)) {
        return NULL; // Error message too large
    }
    strncpy(response_buffer, msg, sizeof(response_buffer) - 1);
    response_buffer[sizeof(response_buffer) - 1] = '\0';
    return response_buffer;
}

// Check if input is JSON by looking for '{' as first non-whitespace character
static int is_json(const char* input) {
    const char* ptr = input;
    while (*ptr && isspace(*ptr)) ptr++;
    return *ptr == '{';
}

// Helper function to append XML tags
void append_xml(cJSON* node, char* buffer, int depth) {
    if (!node) return;

    // Skip if node is an attribute (starts with '@')
    if (node->string && strncmp(node->string, "@", 1) == 0) {
        return;
    }

    // Determine tag name
    const char* tag = node->string ? node->string : "root";
    char* start_tag = (char*)malloc(strlen(tag) + 512);
    if (!start_tag) {
        fprintf(stderr, "Failed to allocate start_tag\n");
        return;
    }
    sprintf(start_tag, "<%s", tag);

    // Add attributes
    cJSON* child = node->child;
    while (child) {
        if (child->string && strncmp(child->string, "@", 1) == 0) {
            char* attr_name = child->string + 1;
            if (cJSON_IsString(child)) {
                sprintf(start_tag + strlen(start_tag), " %s=\"%s\"", attr_name, child->valuestring);
            }
        }
        child = child->next;
    }
    strcat(start_tag, ">");

    // Append start tag
    strcat(buffer, start_tag);
    free(start_tag);

    // Process children
    child = node->child;
    int has_non_attr_children = 0;
    while (child) {
        if (!child->string || strncmp(child->string, "@", 1) != 0) {
            has_non_attr_children = 1;
            if (cJSON_IsObject(child) || cJSON_IsArray(child)) {
                append_xml(child, buffer, depth + 1);
            } else if (cJSON_IsString(child) || cJSON_IsNumber(child)) {
                // Create a new tag for string or number values
                const char* child_tag = child->string ? child->string : "root";
                char* child_start_tag = (char*)malloc(strlen(child_tag) + 4);
                sprintf(child_start_tag, "<%s>", child_tag);
                strcat(buffer, child_start_tag);
                free(child_start_tag);

                if (cJSON_IsString(child)) {
                    strcat(buffer, child->valuestring);
                } else if (cJSON_IsNumber(child)) {
                    char num_str[32];
                    snprintf(num_str, sizeof(num_str), "%g", child->valuedouble);
                    strcat(buffer, num_str);
                }

                char* child_end_tag = (char*)malloc(strlen(child_tag) + 4);
                sprintf(child_end_tag, "</%s>", child_tag);
                strcat(buffer, child_end_tag);
                free(child_end_tag);
            }
        }
        child = child->next;
    }

    // Close tag
    sprintf(buffer + strlen(buffer), "</%s>", tag);
}

// JSON to XML conversion for NFe submission
char* json_to_nfe_xml(const char* json_input) {
    cJSON* json = cJSON_Parse(json_input);
    if (!json) {
        fprintf(stderr, "JSON parsing failed: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }

    // Buffer for XML output
    char* xml = (char*)malloc(16384); // Larger buffer for NFe
    if (!xml) {
        cJSON_Delete(json);
        fprintf(stderr, "Failed to allocate XML buffer\n");
        return NULL;
    }
    xml[0] = '\0';

    // Start XML
    strcat(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    strcat(xml, "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4\">");
    strcat(xml, "<soap:Header><nfeCabecMsg><cUF>41</cUF><versaoDados>4.00</versaoDados></nfeCabecMsg></soap:Header>");
    strcat(xml, "<soap:Body><nfeDadosMsg><enviNFe versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\">");
    strcat(xml, "<idLote>1</idLote><indSinc>1</indSinc><NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">");
    strcat(xml, "<infNFe versao=\"4.00\" Id=\"NFe41150705692150000127550010000111890000000000\">");

    // Process the JSON content
    append_xml(json, xml, 0);

    // Close NFe tags
    strcat(xml, "</infNFe></NFe></enviNFe></nfeDadosMsg></soap:Body></soap:Envelope>");

    fprintf(stderr, "Generated XML: %s\n", xml); // Debug output
    cJSON_Delete(json);
    return xml;
}

// JSON to XML conversion for status_servico
static char* json_to_xml(const char* json_input) {
    cJSON* json = cJSON_Parse(json_input);
    if (!json) {
        fprintf(stderr, "JSON parsing failed: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }

    // Buffer for XML output
    char* xml = (char*)malloc(4096);
    if (!xml) {
        cJSON_Delete(json);
        fprintf(stderr, "Failed to allocate XML buffer\n");
        return NULL;
    }
    xml[0] = '\0';

    // Start XML
    strcat(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");

    cJSON* envelope = cJSON_GetObjectItem(json, "soap:Envelope");
    if (!envelope) {
        fprintf(stderr, "No soap:Envelope found in JSON\n");
        free(xml);
        cJSON_Delete(json);
        return NULL;
    }

    append_xml(envelope, xml, 0);
    cJSON_Delete(json);
    return xml;
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

    char* final_payload = (char*)soap_payload;
    if (is_json(soap_payload)) {
        if (strcmp(operation, "NFeAutorizacao") == 0) {
            final_payload = json_to_nfe_xml(soap_payload);
        } else {
            final_payload = json_to_xml(soap_payload);
        }
        if (!final_payload) {
            fprintf(stderr, "JSON to XML conversion failed\n");
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
            return return_error("JSON to XML conversion failed");
        }
        fprintf(stderr, "Sending XML: %s\n", final_payload); // Debug output
    }

    char* request = (char*)malloc(strlen(final_payload) + 512);
    if (!request) {
        if (final_payload != soap_payload) free(final_payload);
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

    // Set SOAPAction based on operation
    const char* soap_action = (strcmp(operation, "NFeAutorizacao") == 0) ?
        "\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4/nfeAutorizacaoLote\"" :
        "\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4/nfeStatusServicoNF\"";

    sprintf(request,
        "POST /%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/soap+xml; charset=utf-8\r\n"
        "SOAPAction: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", path, host, soap_action, strlen(final_payload), final_payload);
    fprintf(stderr, "HTTP Request: %s\n", request); // Debug output
    free(endpoint);
    if (final_payload != soap_payload) free(final_payload);

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
    char buf[8192];
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

__declspec(dllexport) const char* enviar_nfe(const char* soap_payload) {
    return nfe_request("NFeAutorizacao", soap_payload);
}