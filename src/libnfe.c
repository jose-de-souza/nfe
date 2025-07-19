#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <direct.h>
#include <time.h>
#include <fcntl.h>
#include <io.h>
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

// NFe status enum
typedef enum {
    STATUS_EDITANDO,
    STATUS_EMITIDA,
    STATUS_CONTINGENCIA,
    STATUS_INUTILIZADA
} NFeStatus;

// Static buffer for response and error messages
static char response_buffer[8192] = {0};
static char error_buffer[256] = {0};

static const char* return_error(const char* msg) {
    size_t msg_len = strlen(msg);
    if (msg_len >= sizeof(response_buffer)) {
        strncpy(response_buffer, "Error message too large", sizeof(response_buffer) - 1);
        response_buffer[sizeof(response_buffer) - 1] = '\0';
        return response_buffer;
    }
    strncpy(response_buffer, msg, sizeof(response_buffer) - 1);
    response_buffer[sizeof(response_buffer) - 1] = '\0';
    strncpy(error_buffer, msg, sizeof(error_buffer) - 1);
    error_buffer[sizeof(error_buffer) - 1] = '\0';
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

    if (node->string && strncmp(node->string, "@", 1) == 0) {
        return;
    }

    const char* tag = node->string ? node->string : "root";
    char* start_tag = (char*)malloc(strlen(tag) + 512);
    if (!start_tag) {
        fprintf(stderr, "Failed to allocate start_tag\n");
        return;
    }
    sprintf(start_tag, "<%s", tag);

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

    strcat(buffer, start_tag);
    free(start_tag);

    child = node->child;
    while (child) {
        if (!child->string || strncmp(child->string, "@", 1) != 0) {
            if (cJSON_IsObject(child) || cJSON_IsArray(child)) {
                append_xml(child, buffer, depth + 1);
            } else if (cJSON_IsString(child) || cJSON_IsNumber(child)) {
                const char* child_tag = child->string ? child->string : "root";
                char* child_start_tag = (char*)malloc(strlen(child_tag) + 4);
                sprintf(child_start_tag, "<%s>", child_tag);
                strcat(buffer, child_start_tag);
                free(child_start_tag);

                if (cJSON_IsString(child)) {
                    strcat(buffer, child->valuestring ? child->valuestring : "");
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

    sprintf(buffer + strlen(buffer), "</%s>", tag);
}

// Calculate NFe check digit (cDV) using modulo-11
static char calculate_cdv(const char* key_base) {
    int sum = 0;
    int weights[] = {2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5, 6, 7, 8, 9,
                     2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5, 6, 7, 8, 9,
                     2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4};
    for (int i = 42; i >= 0; i--) {
        sum += (key_base[i] - '0') * weights[42 - i];
    }
    int remainder = sum % 11;
    int cdv = (remainder == 0 || remainder == 1) ? 0 : 11 - remainder;
    return '0' + cdv;
}

// Get current timestamp in yyyy-mm-dd hh:mm:ss format
static void get_current_timestamp(char* timestamp, size_t size) {
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    strftime(timestamp, size, "%Y-%m-%d %H:%M:%S", tm);
}

// Validate timestamp format (yyyy-mm-dd hh:mm:ss)
static int validate_timestamp(const char* timestamp) {
    if (strlen(timestamp) != 19) return 0;
    if (timestamp[4] != '-' || timestamp[7] != '-' || timestamp[10] != ' ' ||
        timestamp[13] != ':' || timestamp[16] != ':') return 0;
    for (int i = 0; i < 19; i++) {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16) continue;
        if (!isdigit(timestamp[i])) return 0;
    }
    return 1;
}

// Check nfe.db for existing nNF and return key, status, and last_cStat
static int check_nfe_db(const char* nNF, char* key_out, NFeStatus* status_out, char* cStat_out) {
    const char* db_path = "C:\\madeiras\\erp\\db\\nfe.db";
    fprintf(stderr, "Checking nfe.db for nNF=%s\n", nNF);
    HANDLE hFile = CreateFile(db_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "nfe.db does not exist: %lu\n", GetLastError());
        return 0; // File doesn't exist
    }

    FILE* file = _fdopen(_open_osfhandle((intptr_t)hFile, _O_RDONLY | _O_TEXT), "r");
    if (!file) {
        CloseHandle(hFile);
        strncpy(error_buffer, "Failed to open nfe.db", sizeof(error_buffer) - 1);
        error_buffer[sizeof(error_buffer) - 1] = '\0';
        fprintf(stderr, "check_nfe_db error: %s\n", error_buffer);
        return -1;
    }

    int found = 0;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char* nNF_db = strtok(line, ";");
        char* key_db = strtok(NULL, ";");
        char* status_db = strtok(NULL, ";");
        char* timestamp_db = strtok(NULL, ";");
        char* cStat_db = strtok(NULL, ";\n");
        if (!nNF_db || !key_db || !status_db || !timestamp_db || !cStat_db ||
            strlen(key_db) != 44 || !validate_timestamp(timestamp_db) ||
            (strcmp(status_db, "EMITIDA") != 0 && strcmp(status_db, "CONTINGENCIA") != 0 &&
             strcmp(status_db, "INUTILIZADA") != 0 && strcmp(status_db, "EDITANDO") != 0) ||
            !isdigit(cStat_db[0])) {
            fclose(file);
            CloseHandle(hFile);
            strncpy(error_buffer, "Malformed nfe.db entry", sizeof(error_buffer) - 1);
            error_buffer[sizeof(error_buffer) - 1] = '\0';
            fprintf(stderr, "check_nfe_db error: %s\n", error_buffer);
            return -1;
        }
        if (strcmp(nNF_db, nNF) == 0) {
            strcpy(key_out, key_db);
            strcpy(cStat_out, cStat_db);
            if (strcmp(status_db, "EMITIDA") == 0) *status_out = STATUS_EMITIDA;
            else if (strcmp(status_db, "CONTINGENCIA") == 0) *status_out = STATUS_CONTINGENCIA;
            else if (strcmp(status_db, "INUTILIZADA") == 0) *status_out = STATUS_INUTILIZADA;
            else *status_out = STATUS_EDITANDO;
            found = 1;
            fprintf(stderr, "Found nNF=%s in nfe.db: key=%s, status=%s, cStat=%s\n", nNF_db, key_db, status_db, cStat_db);
            break;
        }
    }

    fclose(file);
    CloseHandle(hFile);
    fprintf(stderr, "check_nfe_db: %s\n", found ? "Record found" : "No record found");
    return found;
}

// Update or append nfe.db with nNF, key, status, timestamp, and cStat
static int update_nfe_db(const char* nNF, const char* key, NFeStatus status, const char* cStat) {
    const char* db_path = "C:\\madeiras\\erp\\db\\nfe.db";
    const char* temp_path = "C:\\madeiras\\erp\\db\\nfe_temp.db";
    fprintf(stderr, "Updating nfe.db for nNF=%s, key=%s, status=%d, cStat=%s\n", nNF, key, status, cStat);

    _mkdir("C:\\madeiras\\erp\\db");

    char timestamp[20];
    get_current_timestamp(timestamp, sizeof(timestamp));

    HANDLE hFile = CreateFile(db_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    FILE* file = NULL;
    if (hFile != INVALID_HANDLE_VALUE) {
        file = _fdopen(_open_osfhandle((intptr_t)hFile, _O_RDONLY | _O_TEXT), "r");
        if (!file) {
            CloseHandle(hFile);
            strncpy(error_buffer, "Failed to open nfe.db for reading", sizeof(error_buffer) - 1);
            error_buffer[sizeof(error_buffer) - 1] = '\0';
            fprintf(stderr, "update_nfe_db error: %s\n", error_buffer);
            return -1;
        }
    }

    HANDLE hTemp = CreateFile(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        if (file) {
            fclose(file);
            CloseHandle(hFile);
        }
        strncpy(error_buffer, "Failed to create temp nfe.db", sizeof(error_buffer) - 1);
        error_buffer[sizeof(error_buffer) - 1] = '\0';
        fprintf(stderr, "update_nfe_db error: %s\n", error_buffer);
        return -1;
    }
    FILE* temp = _fdopen(_open_osfhandle((intptr_t)hTemp, _O_WRONLY | _O_TEXT), "w");
    if (!temp) {
        if (file) {
            fclose(file);
            CloseHandle(hFile);
        }
        CloseHandle(hTemp);
        strncpy(error_buffer, "Failed to open temp nfe.db", sizeof(error_buffer) - 1);
        error_buffer[sizeof(error_buffer) - 1] = '\0';
        fprintf(stderr, "update_nfe_db error: %s\n", error_buffer);
        return -1;
    }

    int updated = 0;
    char line[256];
    if (file) {
        while (fgets(line, sizeof(line), file)) {
            char* nNF_db = strtok(line, ";");
            char* key_db = strtok(NULL, ";");
            char* status_db = strtok(NULL, ";");
            char* timestamp_db = strtok(NULL, ";");
            char* cStat_db = strtok(NULL, ";\n");
            if (!nNF_db || !key_db || !status_db || !timestamp_db || !cStat_db ||
                strlen(key_db) != 44 || !validate_timestamp(timestamp_db) ||
                (strcmp(status_db, "EMITIDA") != 0 && strcmp(status_db, "CONTINGENCIA") != 0 &&
                 strcmp(status_db, "INUTILIZADA") != 0 && strcmp(status_db, "EDITANDO") != 0) ||
                !isdigit(cStat_db[0])) {
                fclose(file);
                fclose(temp);
                CloseHandle(hFile);
                CloseHandle(hTemp);
                remove(temp_path);
                strncpy(error_buffer, "Malformed nfe.db entry", sizeof(error_buffer) - 1);
                error_buffer[sizeof(error_buffer) - 1] = '\0';
                fprintf(stderr, "update_nfe_db error: %s\n", error_buffer);
                return -1;
            }
            if (nNF_db && strcmp(nNF_db, nNF) == 0) {
                const char* status_str = (status == STATUS_EMITIDA) ? "EMITIDA" :
                                         (status == STATUS_CONTINGENCIA) ? "CONTINGENCIA" :
                                         (status == STATUS_INUTILIZADA) ? "INUTILIZADA" : "EDITANDO";
                fprintf(temp, "%s;%s;%s;%s;%s\n", nNF, key, status_str, timestamp, cStat);
                updated = 1;
            } else {
                fputs(line, temp);
            }
        }
        fclose(file);
        CloseHandle(hFile);
    }

    if (!updated) {
        const char* status_str = (status == STATUS_EMITIDA) ? "EMITIDA" :
                                 (status == STATUS_CONTINGENCIA) ? "CONTINGENCIA" :
                                 (status == STATUS_INUTILIZADA) ? "INUTILIZADA" : "EDITANDO";
        fprintf(temp, "%s;%s;%s;%s;%s\n", nNF, key, status_str, timestamp, cStat);
    }

    fclose(temp);
    CloseHandle(hTemp);
    remove(db_path);
    rename(temp_path, db_path);
    fprintf(stderr, "nfe.db updated successfully\n");
    return 0;
}

// JSON to XML conversion for NFe submission
char* json_to_nfe_xml(const char* json_input) {
    fprintf(stderr, "Entering json_to_nfe_xml with input: %s\n", json_input);
    cJSON* json = cJSON_Parse(json_input);
    if (!json) {
        fprintf(stderr, "JSON parsing failed: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }

    cJSON* ide = cJSON_GetObjectItem(json, "ide");
    if (!ide) {
        fprintf(stderr, "Missing ide object in JSON\n");
        cJSON_Delete(json);
        return NULL;
    }
    cJSON* emit = cJSON_GetObjectItem(json, "emit");
    if (!emit) {
        fprintf(stderr, "Missing emit object in JSON\n");
        cJSON_Delete(json);
        return NULL;
    }
    cJSON* cUF = cJSON_GetObjectItem(ide, "cUF");
    cJSON* mod = cJSON_GetObjectItem(ide, "mod");
    cJSON* serie = cJSON_GetObjectItem(ide, "serie");
    cJSON* nNF = cJSON_GetObjectItem(ide, "nNF");
    cJSON* tpEmis = cJSON_GetObjectItem(ide, "tpEmis");
    cJSON* cNPJ = cJSON_GetObjectItem(emit, "CNPJ");
    if (!cUF || !mod || !serie || !nNF || !tpEmis || !cNPJ || !cJSON_IsString(cUF) || !cJSON_IsString(mod) ||
        !cJSON_IsString(serie) || !cJSON_IsString(nNF) || !cJSON_IsString(tpEmis) || !cJSON_IsString(cNPJ)) {
        fprintf(stderr, "Missing or invalid required fields: cUF=%p, mod=%p, serie=%p, nNF=%p, tpEmis=%p, cNPJ=%p\n",
                cUF, mod, serie, nNF, tpEmis, cNPJ);
        cJSON_Delete(json);
        return NULL;
    }
    fprintf(stderr, "Validated JSON fields: cUF=%s, mod=%s, serie=%s, nNF=%s, tpEmis=%s, cNPJ=%s\n",
            cUF->valuestring, mod->valuestring, serie->valuestring, nNF->valuestring, tpEmis->valuestring, cNPJ->valuestring);

    _mkdir("C:\\madeiras\\erp\\db");

    char nfe_key[45] = {0};
    char cStat[16] = "225";
    NFeStatus status = STATUS_EDITANDO;
    int db_exists = check_nfe_db(nNF->valuestring, nfe_key, &status, cStat);
    if (db_exists < 0) {
        fprintf(stderr, "check_nfe_db error: %s\n", error_buffer);
        cJSON_Delete(json);
        return NULL;
    }

    if (!db_exists) {
        HANDLE hFile = CreateFile("C:\\madeiras\\erp\\db\\nfe.db", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        int is_empty = 1;
        if (hFile != INVALID_HANDLE_VALUE) {
            FILE* file = _fdopen(_open_osfhandle((intptr_t)hFile, _O_RDONLY | _O_TEXT), "r");
            if (file) {
                fseek(file, 0, SEEK_END);
                is_empty = (ftell(file) == 0);
                fclose(file);
                CloseHandle(hFile);
            } else {
                CloseHandle(hFile);
                fprintf(stderr, "Failed to check nfe.db size: %lu\n", GetLastError());
                cJSON_Delete(json);
                return NULL;
            }
        }

        char cNF[9];
        snprintf(cNF, sizeof(cNF), "%08d", rand() % 100000000);
        fprintf(stderr, "Generated cNF: %s\n", cNF);
        char serie_padded[4];
        snprintf(serie_padded, sizeof(serie_padded), "%03d", atoi(serie->valuestring));
        fprintf(stderr, "Padded serie: %s\n", serie_padded);
        char nNF_padded[10];
        snprintf(nNF_padded, sizeof(nNF_padded), "%09d", atoi(nNF->valuestring));
        fprintf(stderr, "Padded nNF: %s\n", nNF_padded);
        char key_base[44];
        snprintf(key_base, sizeof(key_base), "%s%s%s%s%s%s%s%s",
                 cUF->valuestring, "2507", cNPJ->valuestring, mod->valuestring, serie_padded, nNF_padded, tpEmis->valuestring, cNF);
        fprintf(stderr, "Generated key_base: %s\n", key_base);
        if (strlen(key_base) != 43) {
            fprintf(stderr, "Invalid key_base length: %zu, key_base=%s\n", strlen(key_base), key_base);
            cJSON_Delete(json);
            return NULL;
        }
        for (int i = 0; i < 43; i++) {
            if (!isdigit(key_base[i])) {
                fprintf(stderr, "Invalid character in key_base at position %d: %c\n", i, key_base[i]);
                cJSON_Delete(json);
                return NULL;
            }
        }
        char cdv = calculate_cdv(key_base);
        if (!isdigit(cdv)) {
            fprintf(stderr, "Invalid cDV generated: %c\n", cdv);
            cJSON_Delete(json);
            return NULL;
        }
        snprintf(nfe_key, sizeof(nfe_key), "NFe%s%c", key_base, cdv);
        fprintf(stderr, "Generated new key: %s (cNF=%s, cDV=%c)\n", nfe_key, cNF, cdv);

        cJSON* cNF_node = cJSON_GetObjectItem(ide, "cNF");
        if (cNF_node) {
            cJSON_SetValuestring(cNF_node, cNF);
        } else {
            cJSON_AddStringToObject(ide, "cNF", cNF);
        }
        cJSON* cDV_node = cJSON_GetObjectItem(ide, "cDV");
        if (cDV_node) {
            char cdv_str[2] = {cdv, '\0'};
            cJSON_SetValuestring(cDV_node, cdv_str);
        } else {
            char cdv_str[2] = {cdv, '\0'};
            cJSON_AddStringToObject(ide, "cDV", cdv_str);
        }

        if (hFile == INVALID_HANDLE_VALUE || is_empty) {
            hFile = CreateFile("C:\\madeiras\\erp\\db\\nfe.db", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "Failed to create nfe.db: %lu\n", GetLastError());
                cJSON_Delete(json);
                return NULL;
            }
            FILE* file = _fdopen(_open_osfhandle((intptr_t)hFile, _O_WRONLY | _O_TEXT), "w");
            if (!file) {
                CloseHandle(hFile);
                fprintf(stderr, "Failed to open nfe.db for writing: %lu\n", GetLastError());
                cJSON_Delete(json);
                return NULL;
            }
            char timestamp[20];
            get_current_timestamp(timestamp, sizeof(timestamp));
            fprintf(file, "%s;%s;EDITANDO;%s;225\n", nNF->valuestring, nfe_key, timestamp);
            fclose(file);
            CloseHandle(hFile);
            fprintf(stderr, "Created new nfe.db with record: %s;%s;EDITANDO;%s;225\n", nNF->valuestring, nfe_key, timestamp);
        }
    } else {
        fprintf(stderr, "Reusing existing key: %s\n", nfe_key);
    }

    if (nfe_key[0] != '\0') {
        char cNF[9];
        strncpy(cNF, nfe_key + 35, 8);
        cNF[8] = '\0';
        char cdv = nfe_key[43];
        cJSON* cNF_node = cJSON_GetObjectItem(ide, "cNF");
        if (cNF_node) {
            cJSON_SetValuestring(cNF_node, cNF);
        } else {
            cJSON_AddStringToObject(ide, "cNF", cNF);
        }
        cJSON* cDV_node = cJSON_GetObjectItem(ide, "cDV");
        if (cDV_node) {
            char cdv_str[2] = {cdv, '\0'};
            cJSON_SetValuestring(cDV_node, cdv_str);
        } else {
            char cdv_str[2] = {cdv, '\0'};
            cJSON_AddStringToObject(ide, "cDV", cdv_str);
        }
    }

    char* xml = (char*)malloc(16384);
    if (!xml) {
        fprintf(stderr, "Failed to allocate XML buffer\n");
        cJSON_Delete(json);
        return NULL;
    }
    xml[0] = '\0';

    strcat(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    strcat(xml, "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4\">");
    strcat(xml, "<soap:Header><nfeCabecMsg><cUF>41</cUF><versaoDados>4.00</versaoDados></nfeCabecMsg></soap:Header>");
    strcat(xml, "<soap:Body><nfeDadosMsg><enviNFe versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\">");
    strcat(xml, "<idLote>1</idLote><indSinc>1</indSinc><NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">");

    char infNFe_tag[128];
    snprintf(infNFe_tag, sizeof(infNFe_tag), "<infNFe versao=\"4.00\" Id=\"%s\">", nfe_key);
    strcat(xml, infNFe_tag);

    cJSON* child = json->child;
    while (child) {
        append_xml(child, xml, 0);
        child = child->next;
    }

    strcat(xml, "</infNFe></NFe></enviNFe></nfeDadosMsg></soap:Body></soap:Envelope>");

    if (update_nfe_db(nNF->valuestring, nfe_key, STATUS_EDITANDO, cStat) != 0) {
        fprintf(stderr, "update_nfe_db error: %s\n", error_buffer);
        free(xml);
        cJSON_Delete(json);
        return NULL;
    }

    fprintf(stderr, "Generated XML: %s\n", xml);
    cJSON_Delete(json);
    return xml;
}

// JSON to XML conversion for status_servico
static char* json_to_xml(const char* json_input) {
    fprintf(stderr, "Entering json_to_xml with input: %s\n", json_input);
    cJSON* json = cJSON_Parse(json_input);
    if (!json) {
        fprintf(stderr, "JSON parsing failed: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }

    char* xml = (char*)malloc(4096);
    if (!xml) {
        fprintf(stderr, "Failed to allocate XML buffer\n");
        cJSON_Delete(json);
        return NULL;
    }
    xml[0] = '\0';

    strcat(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");

    cJSON* envelope = cJSON_GetObjectItem(json, "soap:Envelope");
    if (!envelope) {
        fprintf(stderr, "No soap:Envelope found in JSON\n");
        free(xml);
        cJSON_Delete(json);
        return NULL;
    }

    append_xml(envelope, xml, 0);
    fprintf(stderr, "Generated XML for status_servico: %s\n", xml);
    cJSON_Delete(json);
    return xml;
}

// Load configuration from system.cfg
static Config* load_config() {
    const char* cfg_path = "C:\\madeiras\\erp\\cfg\\system.cfg";
    fprintf(stderr, "Loading config from %s\n", cfg_path);
    FILE* file = fopen(cfg_path, "r");
    if (!file) {
        fprintf(stderr, "Failed to open system.cfg: %lu\n", GetLastError());
        return NULL;
    }

    Config* config = (Config*)malloc(sizeof(Config));
    if (!config) {
        fclose(file);
        fprintf(stderr, "Failed to allocate config struct\n");
        return NULL;
    }
    config->certificate_path = NULL;
    config->certificate_pass = NULL;
    config->cacerts_path = NULL;
    config->sefaz = NULL;
    config->environment = ENV_DEV;

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
        fprintf(stderr, "Incomplete config: cert_path=%p, cert_pass=%p, cacerts=%p, sefaz=%p\n",
                config->certificate_path, config->certificate_pass, config->cacerts_path, config->sefaz);
        free(config->certificate_path);
        free(config->certificate_pass);
        free(config->cacerts_path);
        free(config->sefaz);
        free(config);
        return NULL;
    }
    fprintf(stderr, "Config loaded: cert_path=%s, sefaz=%s, env=%d\n",
            config->certificate_path, config->sefaz, config->environment);
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
    fprintf(stderr, "Loading endpoint from %s for operation %s\n", cfg_file, operation);
    FILE* file = fopen(cfg_file, "r");
    if (!file) {
        fprintf(stderr, "Failed to open %s: %lu\n", cfg_file, GetLastError());
        return NULL;
    }

    char* endpoint = NULL;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char* name = strtok(line, "=");
        char* url = strtok(NULL, "\n");
        if (name && url && strcmp(name, operation) == 0) {
            endpoint = _strdup(url);
            fprintf(stderr, "Found endpoint: %s\n", endpoint);
            break;
        }
    }
    fclose(file);
    if (!endpoint) {
        fprintf(stderr, "No endpoint found for operation %s\n", operation);
    }
    return endpoint;
}

// Private function to handle SOAP requests
static const char* nfe_request(const char* operation, const char* soap_payload) {
    fprintf(stderr, "Entering nfe_request for operation %s\n", operation);
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Winsock initialization failed: %d\n", WSAGetLastError());
        return return_error("Winsock initialization failed");
    }

    Config* config = load_config();
    if (!config) {
        WSACleanup();
        return return_error("Failed to load system.cfg");
    }

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

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        OSSL_PROVIDER_unload(default_provider);
        OSSL_PROVIDER_unload(legacy_provider);
        free_config(config);
        WSACleanup();
        return return_error("Failed to create SSL context");
    }

    BIO* pfx_file = BIO_new_file(config->certificate_path, "rb");
    if (!pfx_file) {
        fprintf(stderr, "Failed to open PFX file: %s\n", config->certificate_path);
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

    fprintf(stderr, "Connecting to %s\n", host);
    if (BIO_do_connect(bio) != 1) {
        char err_buf[256];
        unsigned long err = ERR_get_error();
        ERR_error_string(err, err_buf);
        int sys_err = WSAGetLastError();
        snprintf(response_buffer, sizeof(response_buffer), "Connection failed: %s (Winsock error: %d)", err_buf, sys_err);

        if (strcmp(operation, "NFeAutorizacao") == 0) {
            cJSON* json = cJSON_Parse(soap_payload);
            if (json) {
                cJSON* ide = cJSON_GetObjectItem(json, "ide");
                if (ide) {
                    cJSON* nNF = cJSON_GetObjectItem(ide, "nNF");
                    if (nNF && cJSON_IsString(nNF)) {
                        char nfe_key[45] = {0};
                        char cStat[16] = "0";
                        NFeStatus status;
                        if (check_nfe_db(nNF->valuestring, nfe_key, &status, cStat) > 0) {
                            update_nfe_db(nNF->valuestring, nfe_key, STATUS_CONTINGENCIA, cStat);
                        }
                    }
                }
                cJSON_Delete(json);
            }
        }

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

        if (strcmp(operation, "NFeAutorizacao") == 0) {
            cJSON* json = cJSON_Parse(soap_payload);
            if (json) {
                cJSON* ide = cJSON_GetObjectItem(json, "ide");
                if (ide) {
                    cJSON* nNF = cJSON_GetObjectItem(ide, "nNF");
                    if (nNF && cJSON_IsString(nNF)) {
                        char nfe_key[45] = {0};
                        char cStat[16] = "0";
                        NFeStatus status;
                        if (check_nfe_db(nNF->valuestring, nfe_key, &status, cStat) > 0) {
                            update_nfe_db(nNF->valuestring, nfe_key, STATUS_CONTINGENCIA, cStat);
                        }
                    }
                }
                cJSON_Delete(json);
            }
        }

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
        fprintf(stderr, "Converting JSON to XML for operation %s\n", operation);
        if (strcmp(operation, "NFeAutorizacao") == 0) {
            final_payload = json_to_nfe_xml(soap_payload);
        } else {
            final_payload = json_to_xml(soap_payload);
        }
        if (!final_payload) {
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
        fprintf(stderr, "Sending XML: %s\n", final_payload);
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
    fprintf(stderr, "HTTP Request: %s\n", request);
    free(endpoint);
    if (final_payload != soap_payload) free(final_payload);

    if (BIO_write(bio, request, (int)strlen(request)) <= 0) {
        char err_buf[256];
        ERR_error_string(ERR_get_error(), err_buf);
        snprintf(response_buffer, sizeof(response_buffer), "Write failed: %s", err_buf);

        if (strcmp(operation, "NFeAutorizacao") == 0) {
            cJSON* json = cJSON_Parse(soap_payload);
            if (json) {
                cJSON* ide = cJSON_GetObjectItem(json, "ide");
                if (ide) {
                    cJSON* nNF = cJSON_GetObjectItem(ide, "nNF");
                    if (nNF && cJSON_IsString(nNF)) {
                        char nfe_key[45] = {0};
                        char cStat[16] = "0";
                        NFeStatus status;
                        if (check_nfe_db(nNF->valuestring, nfe_key, &status, cStat) > 0) {
                            update_nfe_db(nNF->valuestring, nfe_key, STATUS_CONTINGENCIA, cStat);
                        }
                    }
                }
                cJSON_Delete(json);
            }
        }

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

            if (strcmp(operation, "NFeAutorizacao") == 0) {
                cJSON* json = cJSON_Parse(soap_payload);
                if (json) {
                    cJSON* ide = cJSON_GetObjectItem(json, "ide");
                    if (ide) {
                        cJSON* nNF = cJSON_GetObjectItem(ide, "nNF");
                        if (nNF && cJSON_IsString(nNF)) {
                            char nfe_key[45] = {0};
                            char cStat[16] = "0";
                            NFeStatus status;
                            if (check_nfe_db(nNF->valuestring, nfe_key, &status, cStat) > 0) {
                                update_nfe_db(nNF->valuestring, nfe_key, STATUS_CONTINGENCIA, cStat);
                            }
                        }
                    }
                    cJSON_Delete(json);
                }
            }

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
    fprintf(stderr, "Received response: %s\n", response_buffer);

    if (strcmp(operation, "NFeAutorizacao") == 0) {
        cJSON* json = cJSON_Parse(soap_payload);
        if (json) {
            cJSON* ide = cJSON_GetObjectItem(json, "ide");
            if (ide) {
                cJSON* nNF = cJSON_GetObjectItem(ide, "nNF");
                if (nNF && cJSON_IsString(nNF)) {
                    char nfe_key[45] = {0};
                    char cStat[16] = "0";
                    NFeStatus status;
                    if (check_nfe_db(nNF->valuestring, nfe_key, &status, cStat) > 0) {
                        const char* cStat_start = strstr(response_buffer, "<cStat>");
                        if (cStat_start) {
                            cStat_start += 7;
                            const char* cStat_end = strstr(cStat_start, "</cStat>");
                            if (cStat_end) {
                                strncpy(cStat, cStat_start, cStat_end - cStat_start);
                                cStat[cStat_end - cStat_start] = '\0';
                            }
                        }
                        if (strstr(response_buffer, "<cStat>100</cStat>")) {
                            update_nfe_db(nNF->valuestring, nfe_key, STATUS_EMITIDA, cStat);
                        } else if (strstr(response_buffer, "<cStat>225</cStat>")) {
                            update_nfe_db(nNF->valuestring, nfe_key, STATUS_EDITANDO, cStat);
                        } else {
                            update_nfe_db(nNF->valuestring, nfe_key, STATUS_CONTINGENCIA, cStat);
                        }
                        fprintf(stderr, "Updated nfe.db with cStat=%s\n", cStat);
                    }
                }
            }
            cJSON_Delete(json);
        }
    }

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
    fprintf(stderr, "Calling status_servico with payload: %s\n", soap_payload);
    return nfe_request("NfeStatusServico", soap_payload);
}

__declspec(dllexport) const char* enviar_nfe(const char* soap_payload) {
    fprintf(stderr, "Calling enviar_nfe with payload: %s\n", soap_payload);
    srand((unsigned int)time(NULL));
    return nfe_request("NFeAutorizacao", soap_payload);
}