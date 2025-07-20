#include <stdio.h>
#include <windows.h>
#include "src/libnfe.h"

typedef const char* (*StatusServicoFunc)(const char*);
typedef const char* (*EnviarNfeFunc)(const char*);

int main() {
    // Load the DLL
    HMODULE lib = LoadLibraryA("libnfe.dll");
    if (!lib) {
        printf("Failed to load libnfe.dll\n");
        return 1;
    }

    // Get function pointer for status_servico
    StatusServicoFunc status_servico = (StatusServicoFunc)GetProcAddress(lib, "status_servico");
    if (!status_servico) {
        printf("Failed to get status_servico\n");
        FreeLibrary(lib);
        return 1;
    }

    // Get function pointer for enviar_nfe
    EnviarNfeFunc enviar_nfe = (EnviarNfeFunc)GetProcAddress(lib, "enviar_nfe");
    if (!enviar_nfe) {
        printf("Failed to get enviar_nfe\n");
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

    // Read JSON payload for enviar_nfe from test/nfe.json
    FILE* fp = fopen(".\\test\\nfe.json", "r");
    if (!fp) {
        printf("Failed to open .\\test\\nfe.json\n");
        FreeLibrary(lib);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* json_nfe_payload = (char*)malloc(size + 1);
    if (!json_nfe_payload) {
        printf("Failed to allocate memory for JSON NFe payload\n");
        fclose(fp);
        FreeLibrary(lib);
        return 1;
    }
    fread(json_nfe_payload, 1, size, fp);
    json_nfe_payload[size] = '\0';
    fclose(fp);

    // Test XML payload for status_servico
    printf("Testing XML payload:\n");
    const char* xml_response = status_servico(xml_payload);
    if (!xml_response) {
        printf("status_servico returned null for XML payload\n");
        free(json_nfe_payload);
        FreeLibrary(lib);
        return 1;
    }
    printf("XML Response:\n%s\n\n", xml_response);

    // Test JSON payload for status_servico
    printf("Testing JSON payload:\n");
    const char* json_response = status_servico(json_payload);
    if (!json_response) {
        printf("status_servico returned null for JSON payload\n");
        free(json_nfe_payload);
        FreeLibrary(lib);
        return 1;
    }
    printf("JSON Response:\n%s\n\n", json_response);

    // Test JSON payload for enviar_nfe
    printf("Testing NFe JSON payload:\n");
    const char* nfe_response = enviar_nfe(json_nfe_payload);
    if (!nfe_response) {
        printf("enviar_nfe returned null for JSON payload\n");
        free(json_nfe_payload);
        FreeLibrary(lib);
        return 1;
    }
    printf("NFe JSON Response:\n%s\n", nfe_response);

    free(json_nfe_payload);
    FreeLibrary(lib);
    return 0;
}