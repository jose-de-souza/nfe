#ifndef LIBNFE_H
#define LIBNFE_H

#include <oleauto.h>

#ifdef __cplusplus
extern "C" {
#endif

// Each function corresponds to a specific SEFAZ webservice operation.
// The payload for each should be valid JSON for that operation.
// IMPORTANT: The returned BSTR is managed by the DLL and MUST NOT be freed by the caller.
// The pointer is valid only until the next call to any function in this DLL.
// Note: The DLL is not thread-safe due to a shared BSTR response. Use in a single-threaded context.

__declspec(dllexport) BSTR NfeInutilizacao(const char* json_payload); // Cancels an NF-e
__declspec(dllexport) BSTR NfeConsultaProtocolo(const char* json_payload); // Queries NF-e protocol
__declspec(dllexport) BSTR NfeStatusServico(const char* json_payload); // Checks SEFAZ service status
__declspec(dllexport) BSTR NfeConsultaCadastro(const char* json_payload); // Queries taxpayer registration
__declspec(dllexport) BSTR RecepcaoEvento(const char* json_payload); // Submits NF-e events
__declspec(dllexport) BSTR NFeAutorizacao(const char* json_payload); // Authorizes an NF-e
__declspec(dllexport) BSTR NFeRetAutorizacao(const char* json_payload); // Retrieves authorization result

#ifdef __cplusplus
}
#endif

#endif // LIBNFE_H