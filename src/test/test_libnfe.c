#include <stdio.h>
#include <windows.h>
#include <oleauto.h>
#include <objbase.h>
#include <time.h>
#include "cJSON.h"
#include <openssl/applink.c>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

void PrintBstr(BSTR bstr) {
    if (bstr != NULL) {
        wprintf(L"%s\n", bstr);
    } else {
        printf("(null)\n");
    }
    fflush(stdout);
}

char* ReadFileToString(const char* filename) {
    fprintf(stderr, "[test_libnfe.c] [%I64d] Entering ReadFileToString: %s\n", (long long)time(NULL), filename);
    fflush(stderr);

    char full_path[MAX_PATH];
    const char* test_dir = getenv("LIBNFE_TEST_DIR");
    if (!test_dir) test_dir = "test";
    snprintf(full_path, MAX_PATH, "%s\\%s", test_dir, filename);
    fprintf(stderr, "[test_libnfe.c] [%I64d] Full path: %s\n", (long long)time(NULL), full_path);
    fflush(stderr);

    FILE* fp = fopen(full_path, "r");
    if (!fp) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Failed to open %s\n", (long long)time(NULL), full_path);
        fflush(stdout);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fprintf(stderr, "[test_libnfe.c] [%I64d] File size: %ld bytes\n", (long long)time(NULL), size);
    fflush(stderr);

    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Failed to allocate memory for %s\n", (long long)time(NULL), full_path);
        fflush(stdout);
        fclose(fp);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, size, fp);
    buffer[read_size] = '\0';
    fprintf(stderr, "[test_libnfe.c] [%I64d] Read %zu bytes from %s\n", (long long)time(NULL), read_size, full_path);
    fflush(stderr);

    fclose(fp);

    cJSON* json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Invalid JSON in %s: %s\n", (long long)time(NULL), full_path, cJSON_GetErrorPtr());
        fflush(stdout);
        free(buffer);
        return NULL;
    }
    cJSON_Delete(json);
    fprintf(stderr, "[test_libnfe.c] [%I64d] JSON validated for %s\n", (long long)time(NULL), full_path);
    fflush(stderr);

    return buffer;
}

int main() {
    fprintf(stderr, "[test_libnfe.c] [%I64d] Starting main\n", (long long)time(NULL));
    fflush(stderr);

    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Failed to initialize COM library\n", (long long)time(NULL));
        fflush(stdout);
        return 1;
    }
    fprintf(stderr, "[test_libnfe.c] [%I64d] COM initialized\n", (long long)time(NULL));
    fflush(stderr);

    const char* lib_dir = getenv("LIBNFE_LIBS_DIR");
    if (!lib_dir) lib_dir = "libs";
    char dll_path[MAX_PATH];
    snprintf(dll_path, MAX_PATH, "%s\\libnfe.dll", lib_dir);
    fprintf(stderr, "[test_libnfe.c] [%I64d] DLL path: %s\n", (long long)time(NULL), dll_path);
    fflush(stderr);

    HMODULE lib = LoadLibraryA(dll_path);
    if (!lib) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Failed to load %s, error code: %lu\n", (long long)time(NULL), dll_path, GetLastError());
        fflush(stdout);
        CoUninitialize();
        return 1;
    }
    fprintf(stderr, "[test_libnfe.c] [%I64d] libnfe.dll loaded successfully\n", (long long)time(NULL));
    fflush(stdout);

    BSTR (*NfeStatusServico)(const char*);
    BSTR (*NFeAutorizacao)(const char*);
    NfeStatusServico = (BSTR (*)(const char*))GetProcAddress(lib, "NfeStatusServico");
    NFeAutorizacao = (BSTR (*)(const char*))GetProcAddress(lib, "NFeAutorizacao");
    if (!NfeStatusServico || !NFeAutorizacao) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Failed to get function pointers, error code: %lu\n", (long long)time(NULL), GetLastError());
        fflush(stdout);
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }
    fprintf(stderr, "[test_libnfe.c] [%I64d] Function pointers loaded\n", (long long)time(NULL));
    fflush(stderr);

    char* status_payload = ReadFileToString("status_servico.json");
    if (!status_payload) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Failed to read status_servico.json\n", (long long)time(NULL));
        fflush(stdout);
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }
    fprintf(stderr, "[test_libnfe.c] [%I64d] status_servico.json loaded: %s\n", (long long)time(NULL), status_payload);
    fflush(stderr);

    fprintf(stderr, "[test_libnfe.c] [%I64d] Testing NfeStatusServico...\n", (long long)time(NULL));
    fflush(stdout);

    BSTR bstr_status_response = NfeStatusServico(status_payload);
    fprintf(stderr, "[test_libnfe.c] [%I64d] NfeStatusServico returned\n", (long long)time(NULL));
    fflush(stderr);

    printf("[test_libnfe.c] Response: ");
    PrintBstr(bstr_status_response);
    printf("\n");
    fflush(stdout);
    free(status_payload);

    char* json_nfe_payload = ReadFileToString("nfe.json");
    if (!json_nfe_payload) {
        fprintf(stderr, "[test_libnfe.c] [%I64d] Failed to read nfe.json\n", (long long)time(NULL));
        fflush(stdout);
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }
    fprintf(stderr, "[test_libnfe.c] [%I64d] nfe.json loaded: %s\n", (long long)time(NULL), json_nfe_payload);
    fflush(stderr);

    fprintf(stderr, "[test_libnfe.c] [%I64d] Testing NFeAutorizacao...\n", (long long)time(NULL));
    fflush(stdout);

    BSTR bstr_nfe_response = NFeAutorizacao(json_nfe_payload);
    fprintf(stderr, "[test_libnfe.c] [%I64d] NFeAutorizacao returned\n", (long long)time(NULL));
    fflush(stderr);

    printf("[test_libnfe.c] Response: ");
    PrintBstr(bstr_nfe_response);
    printf("\n");
    fflush(stdout);
    free(json_nfe_payload);

    FreeLibrary(lib);
    fprintf(stderr, "[test_libnfe.c] [%I64d] libnfe.dll freed\n", (long long)time(NULL));
    fflush(stderr);

    printf("[test_libnfe.c] Tests finished.\n");
    fflush(stdout);

    CoUninitialize();
    fprintf(stderr, "[test_libnfe.c] [%I64d] COM uninitialized\n", (long long)time(NULL));
    fflush(stderr);

    return 0;
}