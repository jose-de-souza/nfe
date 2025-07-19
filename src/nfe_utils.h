#ifndef NFE_UTILS_H
#define NFE_UTILS_H

#include "cJSON.h"

void append_xml(cJSON* node, char* buffer, int depth);
char* json_to_nfe_xml(const char* json_input);

#endif // NFE_UTILS_H