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
#include <time.h>
#include <signal.h>

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
static volatile int g_interrupted = 0;

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT) {
        g_interrupted = 1;
        fprintf(stderr, "[libnfe.c] [%I64d] Received Ctrl+C via ConsoleCtrlHandler, attempting to exit...\n", (long long)time(NULL));
        fflush(stderr);
        return TRUE;
    }
    return FALSE;
}

void signal_handler(int sig) {
    g_interrupted = 1;
    fprintf(stderr, "[libnfe.c] [%I64d] Received SIGINT, attempting to exit...\n", (long long)time(NULL));
    fflush(stderr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        hModule_this_dll = hinstDLL;
        signal(SIGINT, signal_handler);
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        if (g_bstr_response) {
            SysFreeString(g_bstr_response);
            g_bstr_response = NULL;
        }
    }
    return TRUE;
}

static int check_console_interrupt() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hStdin, &mode)) {
        INPUT_RECORD record[128];
        DWORD events;
        if (PeekConsoleInput(hStdin, record, 128, &events) && events > 0) {
            for (DWORD i = 0; i < events; i++) {
                if (record[i].EventType == KEY_EVENT && 
                    record[i].Event.KeyEvent.bKeyDown && 
                    record[i].Event.KeyEvent.wVirtualKeyCode == VK_CONTROL &&
                    record[i].Event.KeyEvent.dwControlKeyState & LEFT_CTRL_PRESSED) {
                    g_interrupted = 1;
                    fprintf(stderr, "[libnfe.c] [%I64d] Detected Ctrl+C via console input check\n", (long long)time(NULL));
                    fflush(stderr);
                    FlushConsoleInputBuffer(hStdin);
                    return 1;
                }
            }
            FlushConsoleInputBuffer(hStdin);
        }
    }
    return 0;
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
    fprintf(stderr, "[libnfe.c] [%I64d] ERROR: %s\n", (long long)time(NULL), msg);
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

static int verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {
    char buf[256];
    X509* err_cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);

    if (!preverify_ok) {
        X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));
        fprintf(stderr, "[libnfe.c] [%I64d] Certificate verification failed at depth %d: %s, subject: %s\n",
                (long long)time(NULL), depth, X509_verify_cert_error_string(err), buf);
        fflush(stderr);
    } else {
        fprintf(stderr, "[libnfe.c] [%I64d] Certificate verification at depth %d: OK\n",
                (long long)time(NULL), depth);
        fflush(stderr);
    }
    return preverify_ok;
}

static BSTR nfe_service_request(const char* service_url, const Config* config, const char* user_payload) {
    fprintf(stderr, "[libnfe.c] [%I64d] Entering nfe_service_request, URL: %s, Payload: %s\n", (long long)time(NULL), service_url, user_payload);
    fflush(stderr);

    if (!service_url || !config || !user_payload) {
        return return_error("Invalid input parameters (URL, config, or payload missing)", 0);
    }

    // Create JSON payload
    cJSON* wrapper = cJSON_CreateObject();
    cJSON* config_json = cJSON_CreateObject();
    cJSON* payload_json = cJSON_Parse(user_payload);
    if (!payload_json) {
        cJSON_Delete(wrapper);
        return return_error("Invalid user JSON payload", 0);
    }
    cJSON_AddItemToObject(wrapper, "payload", payload_json);
    cJSON_AddStringToObject(config_json, "sefaz", config->sefaz);
    cJSON_AddNumberToObject(config_json, "environment", config->environment);
    cJSON_AddItemToObject(wrapper, "config", config_json);
    char* final_payload = cJSON_PrintUnformatted(wrapper);
    cJSON_Delete(wrapper);
    if (!final_payload) {
        return return_error("Failed to create JSON payload", 0);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] JSON payload created: %s\n", (long long)time(NULL), final_payload);
    fflush(stderr);

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        free(final_payload);
        return return_error("Winsock initialization failed", 0);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Winsock initialized\n", (long long)time(NULL));
    fflush(stderr);

    // Initialize OpenSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    fprintf(stderr, "[libnfe.c] [%I64d] OpenSSL initialized\n", (long long)time(NULL));
    fflush(stderr);

    // Create SSL context
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        free(final_payload);
        WSACleanup();
        return return_error("Failed to create SSL_CTX", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] SSL_CTX created\n", (long long)time(NULL));
    fflush(stderr);

    // Set minimum TLS version to 1.2
    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION) != 1) {
        free(final_payload);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to set TLS 1.2 minimum version", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] TLS 1.2 minimum version set\n", (long long)time(NULL));
    fflush(stderr);

    // Load client certificate
    FILE* pfx_file = fopen(config->certificate_path, "rb");
    if (!pfx_file) {
        free(final_payload);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to open client PFX file", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] PFX file opened: %s\n", (long long)time(NULL), config->certificate_path);
    fflush(stderr);

    PKCS12* pfx = d2i_PKCS12_fp(pfx_file, NULL);
    fclose(pfx_file);
    if (!pfx) {
        free(final_payload);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to parse PFX file", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] PFX file parsed\n", (long long)time(NULL));
    fflush(stderr);

    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    if (!PKCS12_parse(pfx, config->certificate_pass, &pkey, &cert, NULL)) {
        free(final_payload);
        PKCS12_free(pfx);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to parse PKCS12 data. Check password", 1);
    }
    PKCS12_free(pfx);
    fprintf(stderr, "[libnfe.c] [%I64d] PKCS12 data parsed\n", (long long)time(NULL));
    fflush(stderr);

    if (SSL_CTX_use_certificate(ssl_ctx, cert) <= 0) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to use client certificate", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Client certificate loaded\n", (long long)time(NULL));
    fflush(stderr);

    if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) <= 0) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to use private key", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Private key loaded\n", (long long)time(NULL));
    fflush(stderr);

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Private key does not match certificate", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Private key verified\n", (long long)time(NULL));
    fflush(stderr);

    // Load CA certificate
    if (SSL_CTX_load_verify_locations(ssl_ctx, config->cacerts_path, NULL) != 1) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to load CA certificate", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] CA certificate loaded: %s\n", (long long)time(NULL), config->cacerts_path);
    fflush(stderr);

    // Set verification mode with custom callback
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);
    fprintf(stderr, "[libnfe.c] [%I64d] SSL verification mode set to peer with callback\n", (long long)time(NULL));
    fflush(stderr);

    // Parse URL
    const char *url_prefix = "https://";
    const char *host_start = (strncmp(service_url, url_prefix, strlen(url_prefix)) == 0) ? service_url + strlen(url_prefix) : service_url;
    const char *path_start = strchr(host_start, '/');
    if (!path_start) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Invalid service URL format", 1);
    }
    char host_and_port[256];
    size_t host_len = path_start - host_start;
    strncpy(host_and_port, host_start, host_len);
    host_and_port[host_len] = '\0';
    const char *path = path_start;
    fprintf(stderr, "[libnfe.c] [%I64d] Parsed URL: Host=%s, Path=%s\n", (long long)time(NULL), host_and_port, path);
    fflush(stderr);

    // Replace localhost with 127.0.0.1 to avoid resolution issues
    if (strcmp(host_and_port, "localhost:5001") == 0) {
        strcpy(host_and_port, "127.0.0.1:5001");
        fprintf(stderr, "[libnfe.c] [%I64d] Replaced localhost with 127.0.0.1:5001\n", (long long)time(NULL));
        fflush(stderr);
    }

    // Create BIO
    BIO* bio = BIO_new_ssl_connect(ssl_ctx);
    if (!bio) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to create BIO", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] BIO created\n", (long long)time(NULL));
    fflush(stderr);

    SSL* ssl = NULL;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to initialize SSL", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] SSL initialized\n", (long long)time(NULL));
    fflush(stderr);

    // Set SNI hostname (use only hostname, not port)
    char hostname[256];
    strncpy(hostname, host_and_port, sizeof(hostname));
    char* port = strchr(hostname, ':');
    if (port) *port = '\0'; // Remove port for SNI
    if (SSL_set_tlsext_host_name(ssl, hostname) != 1) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to set SNI hostname", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] SNI hostname set: %s\n", (long long)time(NULL), hostname);
    fflush(stderr);

    BIO_set_conn_hostname(bio, host_and_port);
    fprintf(stderr, "[libnfe.c] [%I64d] BIO hostname set: %s\n", (long long)time(NULL), host_and_port);
    fflush(stderr);

    // Set non-blocking for connect with retries
    BIO_set_nbio(bio, 1);
    fprintf(stderr, "[libnfe.c] [%I64d] BIO set to non-blocking for connect\n", (long long)time(NULL));
    fflush(stderr);

    // Attempt connection with retries
    int connect_attempts = 0;
    int max_attempts = 50;
    time_t start_time = time(NULL);
    while (connect_attempts < max_attempts && !g_interrupted) {
        connect_attempts++;
        if (BIO_do_connect(bio) > 0) {
            fprintf(stderr, "[libnfe.c] [%I64d] Connected to server after %d attempts\n", (long long)time(NULL), connect_attempts);
            fflush(stderr);
            break;
        }
        check_console_interrupt();
        int ssl_err = SSL_get_error(ssl, BIO_do_connect(bio));
        if (!BIO_should_retry(bio)) {
            char err_msg[256];
            unsigned long openssl_err = ERR_get_error();
            ERR_error_string_n(openssl_err, err_msg, sizeof(err_msg));
            snprintf(err_msg, sizeof(err_msg), "BIO_do_connect failed after %d attempts, SSL error: %d, OpenSSL error: %s",
                     connect_attempts, ssl_err, ERR_reason_error_string(openssl_err));
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error(err_msg, 1);
        }
        if ((time(NULL) - start_time) > 5) {
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("BIO_do_connect timed out after 5 seconds", 1);
        }
        fprintf(stderr, "[libnfe.c] [%I64d] BIO_do_connect attempt %d, SSL error: %d\n",
                (long long)time(NULL), connect_attempts, ssl_err);
        fflush(stderr);
        Sleep(50);
    }

    if (g_interrupted) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Operation interrupted by Ctrl+C during connect", 1);
    }

    if (connect_attempts >= max_attempts) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("BIO_do_connect failed after maximum attempts", 1);
    }

    // Verify server certificate
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "Server certificate verification failed: %s", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error(err_msg, 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Server certificate verified\n", (long long)time(NULL));
    fflush(stderr);

    // Set socket to non-blocking
    long sock_fd = BIO_get_fd(bio, NULL);
    if (sock_fd != -1) {
        u_long nonblock = 1;
        if (ioctlsocket((SOCKET)sock_fd, FIONBIO, &nonblock) != 0) {
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("Failed to set socket to non-blocking", 1);
        }
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        if (setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) != 0) {
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("Failed to set socket receive timeout", 1);
        }
        if (setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) != 0) {
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("Failed to set socket send timeout", 1);
        }
        fprintf(stderr, "[libnfe.c] [%I64d] Socket set to non-blocking and timeouts set to 5 seconds\n", (long long)time(NULL));
        fflush(stderr);
    }

    // Send HTTP request
    char request_header[1024];
    size_t payload_len = strlen(final_payload);
    int header_len = snprintf(request_header, sizeof(request_header),
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        path, host_and_port, payload_len);
    fprintf(stderr, "[libnfe.c] [%I64d] Request header: %s\n", (long long)time(NULL), request_header);
    fflush(stderr);

    // Set BIO to non-blocking for send
    BIO_set_nbio(bio, 1);
    fprintf(stderr, "[libnfe.c] [%I64d] BIO set to non-blocking for send\n", (long long)time(NULL));
    fflush(stderr);

    int bytes_written = 0;
    int write_attempts = 0;
    int max_write_attempts = 50;
    start_time = time(NULL);
    while (write_attempts < max_write_attempts && bytes_written < header_len && !g_interrupted) {
        check_console_interrupt();
        int result = BIO_write(bio, request_header + bytes_written, header_len - bytes_written);
        if (result > 0) {
            bytes_written += result;
            fprintf(stderr, "[libnfe.c] [%I64d] Wrote %d bytes of header, total: %d\n", (long long)time(NULL), result, bytes_written);
            fflush(stderr);
        } else if (result == 0 || BIO_should_retry(bio)) {
            write_attempts++;
            Sleep(50);
        } else {
            char err_msg[256];
            unsigned long openssl_err = ERR_get_error();
            int ssl_err = SSL_get_error(ssl, result);
            ERR_error_string_n(openssl_err, err_msg, sizeof(err_msg));
            snprintf(err_msg, sizeof(err_msg), "Failed to write request header: SSL error: %d, OpenSSL error: %s", ssl_err, ERR_reason_error_string(openssl_err));
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error(err_msg, 1);
        }
        if ((time(NULL) - start_time) > 5) {
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("BIO_write for header timed out after 5 seconds", 1);
        }
    }

    if (g_interrupted) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Operation interrupted by Ctrl+C during header write", 1);
    }

    if (bytes_written < header_len) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to write complete request header after maximum attempts", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Request header sent: %d bytes\n", (long long)time(NULL), bytes_written);
    fflush(stderr);

    bytes_written = 0;
    write_attempts = 0;
    start_time = time(NULL);
    while (write_attempts < max_write_attempts && bytes_written < (int)payload_len && !g_interrupted) {
        check_console_interrupt();
        int result = BIO_write(bio, final_payload + bytes_written, payload_len - bytes_written);
        if (result > 0) {
            bytes_written += result;
            fprintf(stderr, "[libnfe.c] [%I64d] Wrote %d bytes of payload, total: %d\n", (long long)time(NULL), result, bytes_written);
            fflush(stderr);
        } else if (result == 0 || BIO_should_retry(bio)) {
            write_attempts++;
            Sleep(50);
        } else {
            char err_msg[256];
            unsigned long openssl_err = ERR_get_error();
            int ssl_err = SSL_get_error(ssl, result);
            ERR_error_string_n(openssl_err, err_msg, sizeof(err_msg));
            snprintf(err_msg, sizeof(err_msg), "Failed to write payload: SSL error: %d, OpenSSL error: %s", ssl_err, ERR_reason_error_string(openssl_err));
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error(err_msg, 1);
        }
        if ((time(NULL) - start_time) > 5) {
            free(final_payload);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("BIO_write for payload timed out after 5 seconds", 1);
        }
    }

    if (g_interrupted) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Operation interrupted by Ctrl+C during payload write", 1);
    }

    if (bytes_written < (int)payload_len) {
        free(final_payload);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Failed to write complete payload after maximum attempts", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Payload sent: %d bytes, content: %s\n", (long long)time(NULL), bytes_written, final_payload);
    free(final_payload);
    fflush(stderr);

    // Read response in non-blocking mode with select
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
        return return_error("Failed to allocate response buffer", 1);
    }
    fprintf(stderr, "[libnfe.c] [%I64d] Response buffer allocated, size: %zu\n", (long long)time(NULL), buffer_size);
    fflush(stderr);

    BIO_set_nbio(bio, 1);
    fprintf(stderr, "[libnfe.c] [%I64d] BIO set to non-blocking for read\n", (long long)time(NULL));
    fflush(stderr);

    int read_attempts = 0;
    int max_read_attempts = 100;
    start_time = time(NULL);
    while (read_attempts < max_read_attempts && !g_interrupted) {
        check_console_interrupt();

        // Check if socket is readable using select
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET((SOCKET)sock_fd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 50000; // 50ms
        int select_result = select((int)sock_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (select_result < 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "select failed: %d", WSAGetLastError());
            free(response_buffer);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error(err_msg, 1);
        } else if (select_result == 0) {
            read_attempts++;
            fprintf(stderr, "[libnfe.c] [%I64d] select timeout, attempt %d\n", (long long)time(NULL), read_attempts);
            fflush(stderr);
            if ((time(NULL) - start_time) > 5) {
                free(response_buffer);
                EVP_PKEY_free(pkey);
                X509_free(cert);
                BIO_free_all(bio);
                SSL_CTX_free(ssl_ctx);
                WSACleanup();
                return return_error("BIO_read timed out after 5 seconds", 1);
            }
            continue;
        }

        // Socket is readable, attempt BIO_read
        int len = BIO_read(bio, response_buffer + total_len, buffer_size - total_len - 1);
        fprintf(stderr, "[libnfe.c] [%I64d] BIO_read attempt %d, returned: %d\n", (long long)time(NULL), read_attempts + 1, len);
        fflush(stderr);
        if (len > 0) {
            total_len += len;
            response_buffer[total_len] = '\0';
            fprintf(stderr, "[libnfe.c] [%I64d] BIO_read returned %d bytes, total: %zu, content: %.100s%s\n",
                    (long long)time(NULL), len, total_len, response_buffer, total_len > 100 ? "..." : "");
            fflush(stderr);
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
                    return return_error("Failed to reallocate response buffer", 1);
                }
                response_buffer = new_buffer;
                fprintf(stderr, "[libnfe.c] [%I64d] Response buffer reallocated, new size: %zu\n", (long long)time(NULL), buffer_size);
                fflush(stderr);
            }
            read_attempts = 0; // Reset attempts on successful read
            // Check for complete HTTP response
            if (strstr(response_buffer, "\r\n\r\n")) {
                char* content_length = strstr(response_buffer, "Content-Length: ");
                if (content_length) {
                    int expected_len = 0;
                    sscanf(content_length + 16, "%d", &expected_len);
                    char* body_start = strstr(response_buffer, "\r\n\r\n") + 4;
                    size_t body_len = total_len - (body_start - response_buffer);
                    if (body_len >= (size_t)expected_len) {
                        fprintf(stderr, "[libnfe.c] [%I64d] Complete HTTP response received (Content-Length: %d)\n", (long long)time(NULL), expected_len);
                        fflush(stderr);
                        break;
                    }
                } else if (strstr(response_buffer, "Connection: close")) {
                    fprintf(stderr, "[libnfe.c] [%I64d] Connection closed, assuming complete response\n", (long long)time(NULL));
                    fflush(stderr);
                    break;
                }
            }
        } else if (len == 0 || SSL_get_error(ssl, len) == SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "[libnfe.c] [%I64d] Connection closed by server\n", (long long)time(NULL));
            fflush(stderr);
            break; // Exit loop on connection close
        } else {
            int ssl_err = SSL_get_error(ssl, len);
            if (BIO_should_retry(bio) || BIO_should_io_special(bio) || ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                read_attempts++;
                fprintf(stderr, "[libnfe.c] [%I64d] BIO_read attempt %d, SSL error: %d, retrying\n", (long long)time(NULL), read_attempts, ssl_err);
                fflush(stderr);
            } else {
                char err_msg[256];
                unsigned long openssl_err = ERR_get_error();
                ERR_error_string_n(openssl_err, err_msg, sizeof(err_msg));
                snprintf(err_msg, sizeof(err_msg), "BIO_read failed, SSL error: %d, OpenSSL error: %s", ssl_err, ERR_reason_error_string(openssl_err));
                free(response_buffer);
                EVP_PKEY_free(pkey);
                X509_free(cert);
                BIO_free_all(bio);
                SSL_CTX_free(ssl_ctx);
                WSACleanup();
                return return_error(err_msg, 1);
            }
        }
        if ((time(NULL) - start_time) > 5) {
            free(response_buffer);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio);
            SSL_CTX_free(ssl_ctx);
            WSACleanup();
            return return_error("BIO_read timed out after 5 seconds", 1);
        }
    }

    if (g_interrupted) {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Operation interrupted by Ctrl+C during read", 1);
    }

    if (read_attempts >= max_read_attempts) {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("BIO_read failed after maximum attempts", 1);
    }

    // Attempt SSL shutdown
    BIO_set_nbio(bio, 0); // Set back to blocking for shutdown
    int shutdown_result = SSL_shutdown(ssl);
    if (shutdown_result == 0) {
        shutdown_result = SSL_shutdown(ssl); // Second call to complete bidirectional shutdown
    }
    if (shutdown_result < 0) {
        char err_msg[256];
        unsigned long openssl_err = ERR_get_error();
        ERR_error_string_n(openssl_err, err_msg, sizeof(err_msg));
        fprintf(stderr, "[libnfe.c] [%I64d] SSL shutdown failed: %s\n", (long long)time(NULL), err_msg);
        fflush(stderr);
    } else {
        fprintf(stderr, "[libnfe.c] [%I64d] SSL shutdown completed\n", (long long)time(NULL));
        fflush(stderr);
    }

    if (total_len <= 0) {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("No data received from server", 1);
    }

    response_buffer[total_len] = '\0';
    fprintf(stderr, "[libnfe.c] [%I64d] RAW RESPONSE BUFFER:\n%s\n", (long long)time(NULL), response_buffer);
    fflush(stderr);

    // Parse HTTP status code
    int http_status = 0;
    if (strncmp(response_buffer, "HTTP/1.1 ", 9) == 0) {
        sscanf(response_buffer + 9, "%d", &http_status);
        fprintf(stderr, "[libnfe.c] [%I64d] HTTP Status: %d\n", (long long)time(NULL), http_status);
        fflush(stderr);
    } else {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Invalid HTTP response format", 1);
    }

    char* body = strstr(response_buffer, "\r\n\r\n");
    if (!body) {
        free(response_buffer);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return return_error("Invalid HTTP response format: No body found", 1);
    }
    body += 4;
    fprintf(stderr, "[libnfe.c] [%I64d] Response body: %s\n", (long long)time(NULL), body);
    fflush(stderr);

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
    fprintf(stderr, "[libnfe.c] [%I64d] BSTR created for response\n", (long long)time(NULL));
    fflush(stderr);

    free(response_buffer);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free_all(bio);
    SSL_CTX_free(ssl_ctx);
    WSACleanup();
    fprintf(stderr, "[libnfe.c] [%I64d] Cleanup complete, returning BSTR\n", (long long)time(NULL));
    fflush(stderr);

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