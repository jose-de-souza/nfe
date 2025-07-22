#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <winsock2.h>
#include <windows.h>
#include <oleauto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/applink.c>
#include <shlwapi.h>

#include "cJSON.h"
#include "libnfe.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "oleaut32.lib")

typedef struct {
    char* certificate_path;
    char* certificate_pass;
    char* cacerts_path;
    char* sefaz;
    int   environment;
    char* url_nfe_inutilizacao;
    char* url_nfe_consulta_protocolo;
    char* url_nfe_status_servico;
    char* url_nfe_consulta_cadastro;
    char* url_recepcao_evento;
    char* url_nfe_autorizacao;
    char* url_nfe_ret_autorizacao;
} Config;

static HMODULE hModule_this_dll = NULL;
static BSTR g_bstr_response = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        hModule_this_dll = hinstDLL;
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_bstr_response) {
            SysFreeString(g_bstr_response);
            g_bstr_response = NULL;
        }
    }
    return TRUE;
}

static BSTR char_to_bstr(const char* utf8_str) {
    if (!utf8_str) return NULL;
    int w_len = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);
    if (w_len == 0) return NULL;
    wchar_t* w_str = (wchar_t*)malloc(w_len * sizeof(wchar_t));
    if (!w_str) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, w_str, w_len);
    BSTR bstr = SysAllocString(w_str);
    free(w_str);
    return bstr;
}

static BSTR return_error(const char* msg, int cleanup_winsock) {
    char error_json[1024];
    snprintf(error_json, sizeof(error_json), "{\"error\": \"%s\"}", msg);
    fprintf(stderr, "[libnfe.c] ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    fflush(stderr);
    if (g_bstr_response) SysFreeString(g_bstr_response);
    g_bstr_response = char_to_bstr(error_json);
    if (cleanup_winsock) WSACleanup();
    return g_bstr_response;
}

static void free_config(Config* config) {
    if (config) {
        free(config->certificate_path);
        free(config->certificate_pass);
        free(config->cacerts_path);
        free(config->sefaz);
        free(config->url_nfe_inutilizacao);
        free(config->url_nfe_consulta_protocolo);
        free(config->url_nfe_status_servico);
        free(config->url_nfe_consulta_cadastro);
        free(config->url_recepcao_evento);
        free(config->url_nfe_autorizacao);
        free(config->url_nfe_ret_autorizacao);
        free(config);
    }
}

static Config* load_config() {
    char dll_path[MAX_PATH], app_home_dir[MAX_PATH], config_path[MAX_PATH];
    const char* config_dir = getenv("LIBNFE_CONFIG_DIR");
    if (!config_dir) config_dir = getenv("USERPROFILE");

    if (GetModuleFileNameA(hModule_this_dll, dll_path, MAX_PATH) == 0) {
        return NULL;
    }

    strncpy(app_home_dir, dll_path, MAX_PATH);
    PathRemoveFileSpecA(app_home_dir);
    PathRemoveFileSpecA(app_home_dir);

    snprintf(config_path, MAX_PATH, "%s\\libnfe.cfg", config_dir ? config_dir : app_home_dir);

    FILE* file = fopen(config_path, "r");
    if (!file) {
        return NULL;
    }

    Config* config = (Config*)calloc(1, sizeof(Config));
    if (!config) {
        fclose(file);
        return NULL;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        char* key = strtok(line, "=");
        char* value = strtok(NULL, "\n\r");
        if (key && value) {
            while (isspace((unsigned char)*value)) value++;
            #define SET_CONFIG_STR(cfg_key, field) if (_stricmp(key, cfg_key) == 0) config->field = _strdup(value)
            #define SET_CONFIG_PATH(cfg_key, field) if (_stricmp(key, cfg_key) == 0) { \
                char full_path[MAX_PATH]; \
                if (PathIsRelativeA(value)) { snprintf(full_path, MAX_PATH, "%s\\%s", app_home_dir, value); config->field = _strdup(full_path); } \
                else { config->field = _strdup(value); } \
            }
            SET_CONFIG_PATH("certificate_path", certificate_path);
            SET_CONFIG_STR("certificate_pass", certificate_pass);
            SET_CONFIG_PATH("cacerts_path", cacerts_path);
            SET_CONFIG_STR("sefaz", sefaz);
            if (_stricmp(key, "environment") == 0) config->environment = atoi(value);
            SET_CONFIG_STR("NfeInutilizacao", url_nfe_inutilizacao);
            SET_CONFIG_STR("NfeConsultaProtocolo", url_nfe_consulta_protocolo);
            SET_CONFIG_STR("NfeStatusServico", url_nfe_status_servico);
            SET_CONFIG_STR("NfeConsultaCadastro", url_nfe_consulta_cadastro);
            SET_CONFIG_STR("RecepcaoEvento", url_recepcao_evento);
            SET_CONFIG_STR("NFeAutorizacao", url_nfe_autorizacao);
            SET_CONFIG_STR("NFeRetAutorizacao", url_nfe_ret_autorizacao);
        }
    }
    fclose(file);
    return config;
}

static BSTR nfe_service_request(const char* service_url, const Config* config, const char* user_payload) {
    if (!service_url) return return_error("Service URL not defined", 0);

    cJSON* wrapper = cJSON_CreateObject();
    cJSON* config_json = cJSON_CreateObject();
    cJSON* payload_json = cJSON_Parse(user_payload);
    if (!payload_json) {
        cJSON_Delete(wrapper);
        return return_error("Invalid user JSON payload.", 0);
    }
    cJSON_AddItemToObject(wrapper, "payload", payload_json);
    cJSON_AddStringToObject(config_json, "sefaz", config->sefaz);
    cJSON_AddNumberToObject(config_json, "environment", config->environment);
    cJSON_AddItemToObject(wrapper, "config", config_json);
    char* final_payload = cJSON_PrintUnformatted(wrapper);
    cJSON_Delete(wrapper);
    if (!final_payload) {
        return return_error("Failed to create JSON payload.", 0);
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        free(final_payload);
        return return_error("Winsock init failed", 0);
    }

    OPENSSL_init_ssl(0, NULL);
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        free(final_payload);
        WSACleanup();
        return return_error("Failed to create SSL_CTX", 1);
    }

    FILE* pfx_file = fopen(config->certificate_path, "rb");
    if (!pfx_file) {
        free(final_payload);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to open client PFX file.", 1);
    }
    
    PKCS12* pfx = d2i_PKCS12_fp(pfx_file, NULL);
    fclose(pfx_file);
    if (!pfx) {
        free(final_payload);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to parse PFX file.", 1);
    }

    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    if (!PKCS12_parse(pfx, config->certificate_pass, &pkey, &cert, NULL)) {
        free(final_payload);
        PKCS12_free(pfx);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to parse PKCS12 data. Check password.", 1);
    }
    PKCS12_free(pfx);

    if (SSL_CTX_use_certificate(ssl_ctx, cert) <= 0 || SSL_CTX_use_PrivateKey(ssl_ctx, pkey) <= 0) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to use client certificate or private key.", 1);
    }
    if (SSL_CTX_load_verify_locations(ssl_ctx, config->cacerts_path, NULL) != 1) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to load CA certificate.", 1);
    }

    const char *url_prefix = "https://";
    const char *host_start = (strncmp(service_url, url_prefix, strlen(url_prefix)) == 0) ? service_url + strlen(url_prefix) : service_url;
    const char *path_start = strchr(host_start, '/');
    if (!path_start) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Invalid service URL format.", 1);
    }
    char host_and_port[256];
    size_t host_len = path_start - host_start;
    strncpy(host_and_port, host_start, host_len);
    host_and_port[host_len] = '\0';
    const char *path = path_start;

    BIO* bio = BIO_new_ssl_connect(ssl_ctx);
    if (!bio) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to create BIO.", 1);
    }
    BIO_set_conn_hostname(bio, host_and_port);

    SSL* ssl = NULL;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to initialize SSL.", 1);
    }

    if (BIO_do_connect(bio) <= 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "Failed to connect to server: %s", ERR_reason_error_string(ERR_get_error()));
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error(BIO_should_retry(bio) ? "Connection timed out." : err_msg, 1);
    }

    long sock_fd = BIO_get_fd(bio, NULL);
    struct timeval tv;
    tv.tv_sec = 10; // Increased timeout to 10 seconds
    tv.tv_usec = 0;
    setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    char request_header[1024];
    size_t payload_len = strlen(final_payload);
    int header_len = sprintf(request_header, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        path, host_and_port, payload_len);
    
    BIO_write(bio, request_header, header_len);
    BIO_write(bio, final_payload, payload_len);
    BIO_flush(bio);
    free(final_payload);

    char* response_buffer = NULL;
    size_t buffer_size = 8192;
    size_t total_len = 0;
    response_buffer = (char*)malloc(buffer_size);
    if (!response_buffer) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to allocate response buffer.", 1);
    }

    int max_attempts = 10;
    int attempts = 0;
    int len;
    while ((len = BIO_read(bio, response_buffer + total_len, buffer_size - total_len - 1)) >= 0) {
        if (len == 0) {
            // Connection closed by server
            break;
        }
        total_len += len;
        if (total_len >= buffer_size - 1) {
            buffer_size *= 2;
            char* new_buffer = (char*)realloc(response_buffer, buffer_size);
            if (!new_buffer) {
                free(response_buffer);
                EVP_PKEY_free(pkey);
                X509_free(cert);
                BIO_free_all(bio);
                SSL_CTX_free(ssl_ctx);
                WSACleanup();
                return return_error("Failed to reallocate response buffer.", 1);
            }
            response_buffer = new_buffer;
        }
        attempts++;
        if (attempts >= max_attempts) {
            free(response_buffer);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("Maximum read attempts reached.", 1);
        }
    }
    
    fprintf(stderr, "[libnfe.c] BIO_read loop finished. Total bytes read: %zu\n", total_len);
    fflush(stderr);

    if (len < 0 && BIO_should_retry(bio)) {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Read operation timed out.", 1);
    }

    if (total_len <= 0) {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("No data received from server.", 1);
    }

    response_buffer[total_len] = '\0';
    fprintf(stderr, "\n--- [libnfe.c] RAW RESPONSE BUFFER ---\n%s\n-------------------------------------\n", response_buffer);
    fflush(stderr);

    // Parse HTTP status code
    int http_status = 0;
    if (strncmp(response_buffer, "HTTP/1.1 ", 9) == 0) {
        sscanf(response_buffer + 9, "%d", &http_status);
        fprintf(stderr, "[libnfe.c] HTTP Status: %d\n", http_status);
        fflush(stderr);
    } else {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Invalid HTTP response format.", 1);
    }

    char* body = strstr(response_buffer, "\r\n\r\n");
    if (!body) {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Invalid HTTP response format: No body found.", 1);
    }
    body += 4;

    if (http_status != 200) {
        char error_msg[1024];
        snprintf(error_msg, sizeof(error_msg), "Server returned HTTP %d: %s", http_status, body);
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error(error_msg, 1);
    }

    if (g_bstr_response) SysFreeString(g_bstr_response);
    g_bstr_response = char_to_bstr(body);
    free(response_buffer);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free_all(bio);
    SSL_CTX_free(ssl_ctx);
    WSACleanup();

    return g_bstr_response;
}

__declspec(dllexport) BSTR NfeInutilizacao(const char* json_payload) {
    Config* config = load_config();
    if (!config) return return_error("Failed to load or parse libnfe.cfg.", 0);
    BSTR response = nfe_service_request(config->url_nfe_inutilizacao, config, json_payload);
    free_config(config);
    return response;
}

__declspec(dllexport) BSTR NfeConsultaProtocolo(const char* json_payload) {
    Config* config = load_config();
    if (!config) return return_error("Failed to load or parse libnfe.cfg.", 0);
    BSTR response = nfe_service_request(config->url_nfe_consulta_protocolo, config, json_payload);
    free_config(config);
    return response;
}

__declspec(dllexport) BSTR NfeStatusServico(const char* json_payload) {
    Config* config = load_config();
    if (!config) return return_error("Failed to load or parse libnfe.cfg.", 0);
    BSTR response = nfe_service_request(config->url_nfe_status_servico, config, json_payload);
    free_config(config);
    return response;
}

__declspec(dllexport) BSTR NfeConsultaCadastro(const char* json_payload) {
    Config* config = load_config();
    if (!config) return return_error("Failed to load or parse libnfe.cfg.", 0);
    BSTR response = nfe_service_request(config->url_nfe_consulta_cadastro, config, json_payload);
    free_config(config);
    return response;
}

__declspec(dllexport) BSTR RecepcaoEvento(const char* json_payload) {
    Config* config = load_config();
    if (!config) return return_error("Failed to load or parse libnfe.cfg.", 0);
    BSTR response = nfe_service_request(config->url_recepcao_evento, config, json_payload);
    free_config(config);
    return response;
}

__declspec(dllexport) BSTR NFeAutorizacao(const char* json_payload) {
    Config* config = load_config();
    if (!config) return return_error("Failed to load or parse libnfe.cfg.", 0);
    BSTR response = nfe_service_request(config->url_nfe_autorizacao, config, json_payload);
    free_config(config);
    return response;
}

__declspec(dllexport) BSTR NFeRetAutorizacao(const char* json_payload) {
    Config* config = load_config();
    if (!config) return return_error("Failed to load or parse libnfe.cfg.", 0);
    BSTR response = nfe_service_request(config->url_nfe_ret_autorizacao, config, json_payload);
    free_config(config);
    return response;
}