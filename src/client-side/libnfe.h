#ifndef LIBNFE_H
#define LIBNFE_H

#include <oleauto.h> // Required for the BSTR type

#ifdef __cplusplus
extern "C" {
#endif

// Each function corresponds to a specific SEFAZ webservice operation.
// The payload for each should be the core data required for that operation, in JSON format.
//
// IMPORTANT: The returned BSTR is managed by the DLL and MUST NOT be freed by the caller.
// The pointer is valid only until the next call to any function in this DLL.

__declspec(dllexport) BSTR NfeInutilizacao(const char* json_payload);
__declspec(dllexport) BSTR NfeConsultaProtocolo(const char* json_payload);
__declspec(dllexport) BSTR NfeStatusServico(const char* json_payload);
__declspec(dllexport) BSTR NfeConsultaCadastro(const char* json_payload);
__declspec(dllexport) BSTR RecepcaoEvento(const char* json_payload);
__declspec(dllexport) BSTR NFeAutorizacao(const char* json_payload);
__declspec(dllexport) BSTR NFeRetAutorizacao(const char* json_payload);

#ifdef __cplusplus
}
#endif

#endif // LIBNFE_H
