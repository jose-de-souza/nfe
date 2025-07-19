#include <stdio.h>
#include <string.h>
#include "cJSON.h"

// Helper function to append XML tags
static void append_xml(cJSON* node, char* buffer, int depth) {
    if (!node) return;
    char indent[256] = {0};
    for (int i = 0; i < depth * 2; i++) indent[i] = ' ';
    
    if (cJSON_IsObject(node)) {
        cJSON* child = node->child;
        while (child) {
            char* tag = child->string;
            if (strncmp(tag, "@", 1) == 0) { // Attributes
                child = child->next;
                continue;
            }
            char* start_tag = (char*)malloc(strlen(tag) + 256);
            sprintf(start_tag, "\n%s<%s", indent, tag);
            
            // Add attributes
            cJSON* attr = node->child;
            while (attr) {
                if (strncmp(attr->string, "@", 1) == 0) {
                    char* attr_name = attr->string + 1; // Skip '@'
                    if (cJSON_IsString(attr)) {
                        sprintf(start_tag + strlen(start_tag), " %s=\"%s\"", attr_name, attr->valuestring);
                    }
                }
                attr = attr->next;
            }
            strcat(start_tag, ">");
            strcat(buffer, start_tag);
            free(start_tag);

            if (cJSON_IsObject(child) || cJSON_IsArray(child)) {
                append_xml(child, buffer, depth + 1);
                sprintf(buffer + strlen(buffer), "\n%s</%s>", indent, tag);
            } else if (cJSON_IsString(child)) {
                strcat(buffer, child->valuestring);
                sprintf(buffer + strlen(buffer), "</%s>", tag);
            } else if (cJSON_IsNumber(child)) {
                char num_str[32];
                snprintf(num_str, sizeof(num_str), "%g", child->valuedouble);
                strcat(buffer, num_str);
                sprintf(buffer + strlen(buffer), "</%s>", tag);
            }
            child = child->next;
        }
    } else if (cJSON_IsArray(node)) {
        cJSON* child = node->child;
        while (child) {
            append_xml(child, buffer, depth);
            child = child->next;
        }
    }
}

// JSON to XML conversion
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

    char* xml_output = json_to_xml(json_payload);
    if (!xml_output) {
        printf("Failed to convert JSON to XML\n");
        return 1;
    }
    printf("Generated XML:\n%s\n", xml_output);
    free(xml_output);
    return 0;
}