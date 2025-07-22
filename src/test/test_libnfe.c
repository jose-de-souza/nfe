#include <stdio.h>
#include <windows.h>
#include <oleauto.h>
#include <objbase.h> // Required for COM initialization
#include "cJSON.h"
#include <openssl/applink.c> // Required for OpenSSL + MSVC

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Helper function to print a BSTR to the console
void PrintBstr(BSTR bstr) {
    if (bstr != NULL) {
        // Use wprintf for wide-character BSTR strings
        wprintf(L"%s\n", bstr);
    } else {
        printf("(null)\n");
    }
    fflush(stdout); // Force the output to be written to the console
}

// Helper function to read a JSON file into a string
char* ReadFileToString(const char* filename) {
    char full_path[MAX_PATH];
    // Use the LIBNFE_TEST_DIR environment variable to find the test files
    const char* test_dir = getenv("LIBNFE_TEST_DIR");
    if (!test_dir) test_dir = "test"; // Default to a 'test' subdirectory
    snprintf(full_path, MAX_PATH, "%s\\%s", test_dir, filename);

    FILE* fp = fopen(full_path, "r");
    if (!fp) {
        printf("[test_libnfe.c] Failed to open %s\n", full_path);
        fflush(stdout);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        printf("[test_libnfe.c] Failed to allocate memory for %s\n", full_path);
        fflush(stdout);
        fclose(fp);
        return NULL;
    }
    size_t read_size = fread(buffer, 1, size, fp);
    buffer[read_size] = '\0';
    fclose(fp);

    // Basic validation to ensure the file content is valid JSON
    cJSON* json = cJSON_Parse(buffer);
    if (!json) {
        printf("[test_libnfe.c] Invalid JSON in %s: %s\n", full_path, cJSON_GetErrorPtr());
        fflush(stdout);
        free(buffer);
        return NULL;
    }
    cJSON_Delete(json);
    return buffer;
}

int main() {
    // Initialize the COM library for the current thread
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) {
        printf("[test_libnfe.c] Failed to initialize COM library\n");
        fflush(stdout);
        return 1;
    }

    // Use the LIBNFE_LIBS_DIR environment variable to find the DLL
    const char* lib_dir = getenv("LIBNFE_LIBS_DIR");
    if (!lib_dir) lib_dir = "libs"; // Default to a 'libs' subdirectory
    char dll_path[MAX_PATH];
    snprintf(dll_path, MAX_PATH, "%s\\libnfe.dll", lib_dir);
    
    HMODULE lib = LoadLibraryA(dll_path);
    if (!lib) {
        printf("[test_libnfe.c] Failed to load %s.\n", dll_path);
        fflush(stdout);
        CoUninitialize();
        return 1;
    }
    printf("[test_libnfe.c] libnfe.dll loaded successfully.\n\n");
    fflush(stdout);

    // Define function pointers with the explicit, standard syntax
    BSTR (*NfeStatusServico)(const char*);
    BSTR (*NFeAutorizacao)(const char*);

    // Cast the result of GetProcAddress to the correct function pointer type
    NfeStatusServico = (BSTR (*)(const char*))GetProcAddress(lib, "NfeStatusServico");
    NFeAutorizacao = (BSTR (*)(const char*))GetProcAddress(lib, "NFeAutorizacao");


    if (!NfeStatusServico || !NFeAutorizacao) {
        printf("[test_libnfe.c] Failed to get one or more function pointers.\n");
        fflush(stdout);
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }

    // --- Test NfeStatusServico ---
    char* status_payload = ReadFileToString("status_servico.json");
    if (!status_payload) {
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }
    
    printf("[test_libnfe.c] Testing NfeStatusServico...\n");
    fflush(stdout);
    
    BSTR bstr_status_response = NfeStatusServico(status_payload);
    printf("[test_libnfe.c] Response: ");
    PrintBstr(bstr_status_response);
    printf("\n");
    fflush(stdout);
    free(status_payload);

    // --- Test NFeAutorizacao ---
    char* json_nfe_payload = ReadFileToString("nfe.json");
    if (!json_nfe_payload) {
        FreeLibrary(lib);
        CoUninitialize();
        return 1;
    }

    printf("[test_libnfe.c] Testing NFeAutorizacao...\n");
    fflush(stdout);

    BSTR bstr_nfe_response = NFeAutorizacao(json_nfe_payload);
    printf("[test_libnfe.c] Response: ");
    PrintBstr(bstr_nfe_response);
    printf("\n");
    fflush(stdout);
    free(json_nfe_payload);
    
    // Clean up resources
    FreeLibrary(lib);

    printf("[test_libnfe.c] Tests finished.\n");
    fflush(stdout);

    // Uninitialize the COM library before exiting
    CoUninitialize();
    return 0;
}
