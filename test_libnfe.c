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

    // XML payload for status_servico
    const char* xml_payload =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\">"
        "<soap:Header><nfeCabecMsg><cUF>41</cUF><versaoDados>4.00</versaoDados></nfeCabecMsg></soap:Header>"
        "<soap:Body><nfeDadosMsg><consStatServ versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\"><tpAmb>2</tpAmb><cUF>41</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap:Body>"
        "</soap:Envelope>";

    // JSON payload for status_servico
    const char* json_payload =
        "{"
        "\"soap:Envelope\": {"
        "\"@xmlns:soap\": \"http://www.w3.org/2003/05/soap-envelope\","
        "\"@xmlns\": \"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\","
        "\"soap:Header\": {"
        "\"nfeCabecMsg\": {"
        "\"cUF\": \"41\","
        "\"versaoDados\": \"4.00\""
        "}"
        "},"
        "\"soap:Body\": {"
        "\"nfeDadosMsg\": {"
        "\"consStatServ\": {"
        "\"@versao\": \"4.00\","
        "\"@xmlns\": \"http://www.portalfiscal.inf.br/nfe\","
        "\"tpAmb\": \"2\","
        "\"cUF\": \"41\","
        "\"xServ\": \"STATUS\""
        "}"
        "}"
        "}"
        "}"
        "}";

    // Test XML payload
    printf("Testing XML payload:\n");
    const char* xml_response = status_servico(xml_payload);
    if (!xml_response) {
        printf("status_servico returned null for XML payload\n");
        FreeLibrary(lib);
        return 1;
    }
    printf("XML Response:\n%s\n\n", xml_response);

    // Test JSON payload
    printf("Testing JSON payload:\n");
    const char* json_response = status_servico(json_payload);
    if (!json_response) {
        printf("status_servico returned null for JSON payload\n");
        FreeLibrary(lib);
        return 1;
    }
    printf("JSON Response:\n%s\n", json_response);

    FreeLibrary(lib);
    return 0;
}