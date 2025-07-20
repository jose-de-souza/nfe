#include <stdio.h>
#include <windows.h>
#include <oleauto.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Define function pointer types for the new BSTR-returning functions
typedef BSTR (*NFeFunction)(const char*);

// Helper to print BSTR to console
void PrintBstr(BSTR bstr) {
    if (bstr != NULL) {
        wprintf(L"%s\n", bstr);
    } else {
        printf("(null)\n");
    }
}

// Helper function to read a file into a string buffer
char* ReadFileToString(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("Failed to open %s\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        printf("Failed to allocate memory for %s\n", filename);
        fclose(fp);
        return NULL;
    }
    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}


int main() {
    // Load the DLL from the libs subdirectory
    HMODULE lib = LoadLibraryA("libs\\libnfe.dll");
    if (!lib) {
        printf("Failed to load libnfe.dll. Make sure it is in the 'libs' subdirectory.\n");
        return 1;
    }
    printf("libnfe.dll loaded successfully.\n\n");

    // Get function pointers
    NFeFunction NfeStatusServico = (NFeFunction)GetProcAddress(lib, "NfeStatusServico");
    NFeFunction NFeAutorizacao = (NFeFunction)GetProcAddress(lib, "NFeAutorizacao");

    if (!NfeStatusServico || !NFeAutorizacao) {
        printf("Failed to get one or more function pointers from the DLL.\n");
        FreeLibrary(lib);
        return 1;
    }

    // --- Test 1: NfeStatusServico ---
    char* status_payload = ReadFileToString("test\\status_servico.json");
    if (!status_payload) {
        FreeLibrary(lib);
        return 1;
    }
    
    printf("Testing NfeStatusServico...\n");
    printf("Payload: (from test\\status_servico.json)\n");
    
    BSTR bstr_status_response = NfeStatusServico(status_payload);
    printf("Response: ");
    PrintBstr(bstr_status_response);
    printf("\n");
    free(status_payload); // Clean up the status payload

    // --- Test 2: NFeAutorizacao ---
    char* json_nfe_payload = ReadFileToString("test\\nfe.json");
    if (!json_nfe_payload) {
        FreeLibrary(lib);
        return 1;
    }

    printf("Testing NFeAutorizacao...\n");
    printf("Payload: (from test\\nfe.json)\n");

    BSTR bstr_nfe_response = NFeAutorizacao(json_nfe_payload);
    printf("Response: ");
    PrintBstr(bstr_nfe_response);
    printf("\n");

    // Cleanup
    free(json_nfe_payload);
    FreeLibrary(lib);

    printf("Tests finished. Press Enter to exit.\n");
    getchar();

    return 0;
}
