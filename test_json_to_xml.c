#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include "src/nfe_utils.h"

// JSON to XML conversion for status_servico
static char* json_to_xml(const char* json_input) {
    cJSON* json = cJSON_Parse(json_input);
    if (!json) {
        fprintf(stderr, "JSON parsing failed: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }

    // Buffer for XML output
    char* xml = (char*)malloc(4096);
    if (!xml) {
        cJSON_Delete(json);
        fprintf(stderr, "Failed to allocate XML buffer\n");
        return NULL;
    }
    xml[0] = '\0';

    // Start XML
    strcat(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");

    cJSON* envelope = cJSON_GetObjectItem(json, "soap:Envelope");
    if (!envelope) {
        fprintf(stderr, "No soap:Envelope found in JSON\n");
        free(xml);
        cJSON_Delete(json);
        return NULL;
    }

    append_xml(envelope, xml, 0);
    cJSON_Delete(json);
    return xml;
}

int main() {
    // Test 1: JSON to XML for status_servico
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

    printf("Testing JSON to XML conversion for status_servico:\n");
    char* xml_output = json_to_xml(json_payload);
    if (!xml_output) {
        printf("Failed to convert JSON to XML for status_servico\n");
        return 1;
    }
    printf("Generated XML for status_servico:\n%s\n\n", xml_output);
    free(xml_output);

    // Test 2: JSON to XML for enviar_nfe
    printf("Testing JSON to XML conversion for enviar_nfe:\n");
    FILE* fp = fopen("test\\nfe.json", "r");
    if (!fp) {
        printf("Failed to open test\\nfe.json\n");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* json_nfe_payload = (char*)malloc(size + 1);
    if (!json_nfe_payload) {
        printf("Failed to allocate memory for JSON NFe payload\n");
        fclose(fp);
        return 1;
    }
    fread(json_nfe_payload, 1, size, fp);
    json_nfe_payload[size] = '\0';
    fclose(fp);

    char* nfe_xml_output = json_to_nfe_xml(json_nfe_payload);
    if (!nfe_xml_output) {
        printf("Failed to convert JSON to XML for enviar_nfe\n");
        free(json_nfe_payload);
        return 1;
    }
    printf("Generated XML for enviar_nfe:\n%s\n", nfe_xml_output);
    free(nfe_xml_output);
    free(json_nfe_payload);

    return 0;
}