#ifndef LIBNFE_H
#define LIBNFE_H

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) const char* status_servico(const char* soap_payload);
__declspec(dllexport) const char* enviar_nfe(const char* soap_payload);

#ifdef __cplusplus
}
#endif

#endif // LIBNFE_H