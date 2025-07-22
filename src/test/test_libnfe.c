#include <stdio.h>
#include <windows.h>
#include <oleauto.h>
#include <objbase.h> // Required for COM initialization
#include "cJSON.h"

// This is mandatory for OpenSSL 3.x with MSVC to link to the application's C runtime.
#include <openssl/applink.c> 

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")     // Required for CoInitializeEx
#pragma comment(lib, "oleaut32.lib")

typedef BSTR (*NFeFunction)(const char*);

void PrintBstr(BSTR bstr) {
    if (bstr != NULL) {
        wprintf(L"%s\n", bstr);
    } else {
        printf("(null)\n");
    }
}

char* ReadFileToString(const char* filename) {
    char full_path[MAX_PATH];
    const char* test_dir = getenv("LIBNFE_TEST_DIR");
    if (!test_dir) test_dir = "test";
    snprintf(full_path, MAX_PATH, "%s\\%s", test_dir, filename);

    FILE* fp = fopen(full_path, "r");
    if (!fp) {
        printf("Failed to open %s\n", full_path);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        printf("Failed to allocate memory for %s\n", full_path);
        fclose(fp);
        return NULL;
    }
    size_t read_size = fread(buffer, 1, size, fp);
    buffer[read_size] = '\0';
    fclose(fp);

    cJSON* json = cJSON_Parse(buffer);
    if (!json) {
        printf("Invalid JSON in %s: %s\n", full_path, cJSON_GetErrorPtr());
        free(buffer);
        return NULL;
    }
    cJSON_Delete(json);
    return buffer;
}

int main() {
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) {
        printf("Failed to initialize COM library\n");
        return 1;
    }

    const char* lib_dir = getenv("LIBNFE_LIBS_DIR");
    if (!lib_dir) lib_dir = "libs";
    char dll_path[MAX_PATH];
    snprintf(dll_path, MAX_PATH, "%s\\libnfe.dll", lib_dir);
    
    HMODULE lib = LoadLibraryA(dll_path);
    if (!lib) {
        printf("Failed to load %s. Make sure it is in the '%s' subdirectory.\n", dll_path, lib_dir);
        CoUninitialize();
        return 1;
    }
    printf("libnfe.dll loaded successfully.\n\n");

    NFeFunction NfeStatusServico = (NFeFunction)GetProcAddress(lib, "NfeStatusServico");
    NFeFunction NFeAutorizacao = (NFeFunction)GetProcAddress(lib, "NFeAutorizacao");

    if (!NfeStatusServico || !NFeAutorizacao) {
        printf("Failed to get one or more function pointers from the DLL.\n");
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }

    char* status_payload = ReadFileToString("status_servico.json");
    if (!status_payload) {
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }
    
    printf("Testing NfeStatusServico...\n");
    printf("Payload: (from %s\\status_servico.json)\n", getenv("LIBNFE_TEST_DIR") ? getenv("LIBNFE_TEST_DIR") : "test");
    
    BSTR bstr_status_response = NfeStatusServico(status_payload);
    printf("Response: ");
    PrintBstr(bstr_status_response);
    printf("\n");
    free(status_payload);

    char* json_nfe_payload = ReadFileToString("nfe.json");
    if (!json_nfe_payload) {
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }

    printf("Testing NFeAutorizacao...\n");
    printf("Payload: (from %s\\nfe.json)\n", getenv("LIBNFE_TEST_DIR") ? getenv("LIBNFE_TEST_DIR") : "test");

    BSTR bstr_nfe_response = NFeAutorizacao(json_nfe_payload);
    printf("Response: ");
    PrintBstr(bstr_nfe_response);
    printf("\n");
    free(json_nfe_payload);
    
    FreeLibrary(lib);

    printf("Tests finished. Press Enter to exit.\n");
    getchar();

    CoUninitialize();
    return 0;
}