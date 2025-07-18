#include <stdio.h>
#include <windows.h>
#include "libnfe.h"

typedef const char* (*StatusServicoFunc)(const char*);

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

    // SOAP payload for status_servico
    const char* soap_payload =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\">"
        "<soap:Header><nfeCabecMsg><cUF>41</cUF><versaoDados>4.00</versaoDados></nfeCabecMsg></soap:Header>"
        "<soap:Body><nfeDadosMsg><consStatServ versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\"><tpAmb>2</tpAmb><cUF>41</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap:Body>"
        "</soap:Envelope>";

    // Call the function
    const char* response = status_servico(soap_payload);
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