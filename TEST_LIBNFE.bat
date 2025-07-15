@echo off
set OPENSSL_MODULES=C:\madeiras\erp\libs
set PATH=%PATH%;C:\madeiras\erp\libs
zig run test_libnfe.zig