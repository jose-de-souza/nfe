# libnfe: A Secure Client-Server Architecture for NF-e Processing

This project provides a robust solution for processing Brazilian Electronic Invoices (NF-e) using a secure client-server architecture.

## Architecture Overview

The system is composed of two main components:

1.  **`nfe-service` (Python Flask Service)**: A backend service that encapsulates all the business logic for NF-e processing. It handles communication with SEFAZ, validates XML, manages digital signatures, and persists all data to a MySQL database. It exposes a secure RESTful API for all NF-e operations.

2.  **`libnfe.dll` (C Client Library)**: A lightweight, high-performance native DLL for Windows. Its sole purpose is to act as a secure bridge between client software (e.g., ERP systems) and the `nfe-service`. It handles the secure communication, ensuring that only authenticated and authorized clients can interact with the service.

This separation of concerns provides significant advantages:
- **Simplified Maintenance**: The complex logic is centralized in the Python service.
- **Scalability**: The `nfe-service` can be scaled independently of the client applications.
- **Flexibility**: Different types of clients (not just C-based ones) can be developed to interact with the service's API.
- **Enhanced Security**: All business logic is protected behind a secure, authenticated API boundary.

## Security Model: Mutual TLS (mTLS)

Communication between `libnfe.dll` and the `nfe-service` is secured using Mutual TLS (mTLS).

- **Server Authentication**: The client DLL verifies the identity of the `nfe-service` using its SSL certificate.
- **Client Authentication**: The `nfe-service` verifies the identity of the client DLL by requiring it to present a trusted client certificate during the TLS handshake.

This ensures that all traffic is encrypted and that both parties are authenticated, preventing unauthorized access to the API.

## API Contract (`nfe-service`)

The `nfe-service` exposes the following RESTful endpoints:

| Method | Endpoint                     | Description                                            |
| :----- | :--------------------------- | :----------------------------------------------------- |
| `POST` | `/api/v1/nfe/autorizacao`    | Submits a new NF-e for processing. Accepts JSON.       |
| `POST` | `/api/v1/nfe/ret-autorizacao`| Queries the result of a previous authorization request.|
| `POST` | `/api/v1/nfe/status-servico` | Checks the health and operational status of SEFAZ.     |
| `POST` | `/api/v1/nfe/...`            | Other endpoints for Inutilização, Eventos, etc.        |


## Workflow

1.  A client application (e.g., an ERP) calls a function in `libnfe.dll` (e.g., `NFeAutorizacao`), passing the invoice data in JSON format.
2.  `libnfe.dll` reads its configuration from `libnfe.cfg` to find the correct service URL.
3.  It establishes a secure mTLS connection to the `nfe-service`.
4.  The DLL sends the JSON payload to the appropriate REST endpoint (e.g., `POST /api/v1/nfe/autorizacao`).
5.  The `nfe-service` receives the request, validates the client's certificate, and processes the NF-e.
6.  The service communicates with SEFAZ, performs all necessary operations, and stores the results in the MySQL database.
7.  A JSON response is returned through the mTLS tunnel to `libnfe.dll`, which then passes it back to the client application as a `BSTR`.

---

### `libnfe.cfg`

```ini
# -----------------------------------------------------------------
# Configuration for libnfe.dll
# -----------------------------------------------------------------
# This file must be in the same directory as the DLL.

# --- Client Certificate Configuration ---
# Path to the client's .pfx certificate file for mTLS authentication.
# Can be a relative path (e.g., certs\client.pfx) or an absolute path.
certificate_path = certs\client.pfx
certificate_pass = client_password

# Path to the CA certificate used to verify the nfe-service's identity.
# Can be a relative or absolute path.
cacerts_path = certs\server_ca.crt


# --- NFe Service Endpoints ---
# These URLs point to your central nfe-service, which then communicates with SEFAZ.
# The server is madeiras.inf.br, and we assume the service runs on port 5001.

NfeInutilizacao=[https://madeiras.inf.br:5001/api/v1/nfe/inutilizacao](https://madeiras.inf.br:5001/api/v1/nfe/inutilizacao)
NfeConsultaProtocolo=[https://madeiras.inf.br:5001/api/v1/nfe/consulta-protocolo](https://madeiras.inf.br:5001/api/v1/nfe/consulta-protocolo)
NfeStatusServico=[https://madeiras.inf.br:5001/api/v1/nfe/status-servico](https://madeiras.inf.br:5001/api/v1/nfe/status-servico)
NfeConsultaCadastro=[https://madeiras.inf.br:5001/api/v1/nfe/consulta-cadastro](https://madeiras.inf.br:5001/api/v1/nfe/consulta-cadastro)
RecepcaoEvento=[https://madeiras.inf.br:5001/api/v1/nfe/recepcao-evento](https://madeiras.inf.br:5001/api/v1/nfe/recepcao-evento)
NFeAutorizacao=[https://madeiras.inf.br:5001/api/v1/nfe/autorizacao](https://madeiras.inf.br:5001/api/v1/nfe/autorizacao)
NFeRetAutorizacao=[https://madeiras.inf.br:5001/api/v1/nfe/ret-autorizacao](https://madeiras.inf.br:5001/api/v1/nfe/ret-autorizacao)


# --- Operational Context ---
# This information is sent with every request to the nfe-service.

# Target state/federation unit (e.g., pr, sp, mg)
sefaz = pr

# Target environment (1 for Production, 2 for Homologation/Testing)
environment = 2


## Building
Assumption: Microsoft's C/C++ extension is installed

**Ctrl + Shift + B on VSCode**

## Find out the functions exported by a DLL
```bash
dumpbin zig-out\bin\libnfe.dll
```

## Find out the architecture of a DLL (32 or 64 bits)
```bash
dumpbin /headers build\libnfe.dll |find "machine"
```

## OpenSSL for Windows

```bash
[Download OpenSSL installer for Windows](https://slproweb.com/products/Win32OpenSSL.html)
```

## Get cacerts.pem

```bash
openssl s_client -connect homologacao.nfe.sefa.pr.gov.br:443 -showcerts > cacerts.pem
```
## Create a Firewall rule to allow mTLS locally
### Find out the exact python.exe location
On Powershell (Admin not needed)
```bash
(Get-Command python).Source
```
Then run on Powershell as Admin:
```bash
New-NetFirewallRule -DisplayName "Allow NFe Service (Python)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5001 -Program "C:\Program Files\Python313\python.exe"
```

## Test the Local server

```bash
curl -v --cert C:\madeiras\erp\certificates\certificate.pfx:123 --cacert C:\madeiras\erp\certificates\cacerts.pem -X POST -H "Content-Type: application/json" -d "{\"consStatServ\":{\"versao\":\"4.00\",\"tpAmb\":\"2\",\"cUF\":\"41\",\"xServ\":\"STATUS\"}}" https://localhost:5001/api/v1/nfe/status-servico
```