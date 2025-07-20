#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <winsock2.h>
#include <windows.h>
#include <oleauto.h> // For BSTR functions
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <shlwapi.h> // For PathRemoveFileSpecA

#include "cJSON.h"  // For JSON manipulation
#include "libnfe.h" // Header for exported functions

#pragma comment(lib, "shlwapi.lib") // For Path... functions
#pragma comment(lib, "ws2_32.lib")   // For Winsock functions
#pragma comment(lib, "oleaut32.lib")// For BSTR functions

// --- Configuration Structures ---
typedef struct {
    char* certificate_path;
    char* certificate_pass;
    char* cacerts_path;
    char* sefaz;
    int   environment;
    // Specific endpoints
    char* url_nfe_inutilizacao;
    char* url_nfe_consulta_protocolo;
    char* url_nfe_status_servico;
    char* url_nfe_consulta_cadastro;
    char* url_recepcao_evento;
    char* url_nfe_autorizacao;
    char* url_nfe_ret_autorizacao;
} Config;

static HMODULE hModule_this_dll = NULL;
static BSTR g_bstr_response = NULL; // Static BSTR to hold the last response

// --- DLL Main ---
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

// --- Helper Functions ---
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

static BSTR return_error(const char* msg) {
    char error_json[512];
    snprintf(error_json, sizeof(error_json), "{\"error\": \"%s\"}", msg);
    fprintf(stderr, "ERROR: %s\n", msg);
    if (g_bstr_response) SysFreeString(g_bstr_response);
    g_bstr_response = char_to_bstr(error_json);
    return g_bstr_response;
}

static void free_config(Config* config) {
    if (config) {
        free(config->certificate_path); free(config->certificate_pass); free(config->cacerts_path); free(config->sefaz);
        free(config->url_nfe_inutilizacao); free(config->url_nfe_consulta_protocolo); free(config->url_nfe_status_servico);
        free(config->url_nfe_consulta_cadastro); free(config->url_recepcao_evento); free(config->url_nfe_autorizacao);
        free(config->url_nfe_ret_autorizacao);
        free(config);
    }
}

static Config* load_config() {
    char dll_path[MAX_PATH], app_home_dir[MAX_PATH], config_path[MAX_PATH];
    
    if (GetModuleFileNameA(hModule_this_dll, dll_path, MAX_PATH) == 0) {
        fprintf(stderr, "ERROR: Failed to get DLL module path.\n"); return NULL;
    }
    
    // app_home_dir is the parent of the DLL's directory (e.g., C:\madeiras\erp)
    strncpy(app_home_dir, dll_path, MAX_PATH);
    PathRemoveFileSpecA(app_home_dir); // Removes libnfe.dll -> C:\madeiras\erp\libs
    PathRemoveFileSpecA(app_home_dir); // Removes libs -> C:\madeiras\erp
    
    snprintf(config_path, MAX_PATH, "%s\\cfg\\libnfe.cfg", app_home_dir);
    
    FILE* file = fopen(config_path, "r");
    if (!file) { fprintf(stderr, "ERROR: Failed to open %s.\n", config_path); return NULL; }

    Config* config = (Config*)calloc(1, sizeof(Config));
    if (!config) { fclose(file); return NULL; }

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

// --- Core Logic ---
static BSTR nfe_service_request(const char* service_url, const Config* config, const char* user_payload) {
    if (!service_url) return return_error("Service URL for this operation is not defined in libnfe.cfg");

    cJSON* wrapper = cJSON_CreateObject();
    cJSON* config_json = cJSON_CreateObject();
    cJSON* payload_json = cJSON_Parse(user_payload);
    if (!payload_json) { cJSON_Delete(wrapper); return return_error("Invalid user JSON payload."); }
    cJSON_AddItemToObject(wrapper, "payload", payload_json);
    cJSON_AddStringToObject(config_json, "sefaz", config->sefaz);
    cJSON_AddNumberToObject(config_json, "environment", config->environment);
    cJSON_AddItemToObject(wrapper, "config", config_json);
    char* final_payload = cJSON_PrintUnformatted(wrapper);
    cJSON_Delete(wrapper);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) { free(final_payload); return return_error("Winsock init failed"); }
    
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    
    FILE* pfx_file = fopen(config->certificate_path, "rb");
    if (!pfx_file) { free(final_payload); SSL_CTX_free(ssl_ctx); WSACleanup(); return return_error("Failed to open client PFX file."); }
    PKCS12* pfx = d2i_PKCS12_fp(pfx_file, NULL);
    fclose(pfx_file);
    if (!pfx) { free(final_payload); SSL_CTX_free(ssl_ctx); WSACleanup(); return return_error("Failed to parse client PFX file."); }
    
    EVP_PKEY* pkey = NULL; X509* cert = NULL;
    if (!PKCS12_parse(pfx, config->certificate_pass, &pkey, &cert, NULL)) { free(final_payload); PKCS12_free(pfx); SSL_CTX_free(ssl_ctx); WSACleanup(); return return_error("Failed to parse PFX, check password."); }
    PKCS12_free(pfx);

    SSL_CTX_use_certificate(ssl_ctx, cert);
    SSL_CTX_use_PrivateKey(ssl_ctx, pkey);
    SSL_CTX_load_verify_locations(ssl_ctx, config->cacerts_path, NULL);

    char host[256], path[1024]; int port;
    sscanf(service_url, "https://%[^:]:%d%s", host, &port, path);

    BIO* bio = BIO_new_ssl_connect(ssl_ctx);
    BIO_set_conn_hostname(bio, host);
    BIO_set_conn_int_port(bio, &port);
    
    if (BIO_do_connect(bio) <= 0) { /* ... error handling ... */ }

    char request[2048];
    sprintf(request, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
        path, host, strlen(final_payload), final_payload);
    
    BIO_write(bio, request, strlen(request));
    free(final_payload);
    
    char response_buffer[8192];
    int len = BIO_read(bio, response_buffer, sizeof(response_buffer) - 1);
    response_buffer[len > 0 ? len : 0] = '\0';
    char* body = strstr(response_buffer, "\r\n\r\n");
    
    EVP_PKEY_free(pkey); X509_free(cert); BIO_free_all(bio); SSL_CTX_free(ssl_ctx); WSACleanup();

    if (g_bstr_response) SysFreeString(g_bstr_response);
    g_bstr_response = char_to_bstr(body ? body + 4 : "");
    return g_bstr_response;
}

// --- Exported Functions ---
#define IMPLEMENT_NFE_FUNCTION(func_name, url_field) \
__declspec(dllexport) BSTR func_name(const char* json_payload) { \
    Config* config = load_config(); \
    if (!config) return return_error("Failed to load or parse libnfe.cfg."); \
    BSTR response = nfe_service_request(config->url_field, config, json_payload); \
    free_config(config); \
    return response; \
}

IMPLEMENT_NFE_FUNCTION(NfeInutilizacao, url_nfe_inutilizacao)
IMPLEMENT_NFE_FUNCTION(NfeConsultaProtocolo, url_nfe_consulta_protocolo)
IMPLEMENT_NFE_FUNCTION(NfeStatusServico, url_nfe_status_servico)
IMPLEMENT_NFE_FUNCTION(NfeConsultaCadastro, url_nfe_consulta_cadastro)
IMPLEMENT_NFE_FUNCTION(RecepcaoEvento, url_recepcao_evento)
IMPLEMENT_NFE_FUNCTION(NFeAutorizacao, url_nfe_autorizacao)
IMPLEMENT_NFE_FUNCTION(NFeRetAutorizacao, url_nfe_ret_autorizacao)
