#include <stdio.h>
#include <windows.h>
#include "libnfe.h"

typedef const char* (*StatusServicoFunc)(void);

int main() {
    // Load the DLL
    HMODULE lib = LoadLibraryA("libnfe.dll");
    if (!lib) {
        printf("Failed to load libnfe.dll\n");
        return 1;
    }

    // Get function pointer
    StatusServicoFunc status_servico = (StatusServicoFunc)GetProcAddress(lib, "status_servico");
    if (!status_servico) {
        printf("Failed to get status_servico\n");
        FreeLibrary(lib);
        return 1;
    }

    // Call the function
    const char* response = status_servico();
    if (!response) {
        printf("status_servico returned null\n");
        FreeLibrary(lib);
        return 1;
    }

    // Print response
    printf("Response:\n%s\n", response);

    FreeLibrary(lib);
    return 0;
}