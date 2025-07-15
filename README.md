# libnfe
## Nota Fiscal Eletronica

## Limpar o cache
```bash
rmdir /s /q .zig-cache
```

## Compilar
```bash
zig build
```
## Ver as funcoes exportadas pela dll
```bash
dumpbin zig-out\bin\libnfe.dll
```

## Testar a dll
Antes de executar o teste, e necessario copiar libnfe.dll para ```C:\madeiras\erp\libs```
```bash
copy zig-out\bin\libnfe.dll C:\madeiras\erp\libs
```
e executar 
```bash
SET_ENV.bat
```

```bash
zig run test_libnfe.zig -- -lkernel32 -I "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um"
```

## Instalar OpenSSL no Windows

```bash
https://slproweb.com/products/Win32OpenSSL.html
```

## Obter cacerts.pem

```bash
openssl s_client -connect homologacao.nfe.sefa.pr.gov.br:443 -showcerts > cacerts.pem
```
