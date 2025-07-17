# libnfe
## Nota Fiscal Eletronica

## Building
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
