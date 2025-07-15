const std = @import("std");
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/pkcs12.h");
    @cInclude("openssl/provider.h");
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/x509.h");
});

const AppError = error{
    OpenSSLInitFailed,
    OpenSSLCryptoInitFailed,
    DefaultProviderFailed,
    LegacyProviderFailed,
    SSLContextCreationFailed,
    PFXFileOpenFailed,
    PFXLoadFailed,
    PFXParseFailed,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    CACertsLoadFailed,
    BIOCreationFailed,
    SSLRetrieveFailed,
    HostnameSetFailed,
    ConnectionFailed,
    RequestTooLarge,
    WriteFailed,
    TLSVerifyFailed,
    ReadFailed,
    MemoryAllocationFailed,
    ResponseTooLarge,
};

// Static buffer for the response
var response_buffer: [4096:0]u8 = undefined;

export fn status_servico() ?[*:0]const u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Full OpenSSL initialization
    if (c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, @as(?*const c.OPENSSL_INIT_SETTINGS, null)) != 1) {
        return returnError("OpenSSL initialization failed");
    }
    if (c.OPENSSL_init_crypto(c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS | c.OPENSSL_INIT_ADD_ALL_CIPHERS | c.OPENSSL_INIT_ADD_ALL_DIGESTS, @as(?*const c.OPENSSL_INIT_SETTINGS, null)) != 1) {
        return returnError("OpenSSL crypto initialization failed");
    }

    // Load default provider
    const default_provider = c.OSSL_PROVIDER_load(null, "default") orelse {
        return returnError("Failed to load default provider");
    };
    defer _ = c.OSSL_PROVIDER_unload(default_provider);

    // Load legacy provider
    const legacy_provider = c.OSSL_PROVIDER_load(null, "legacy") orelse {
        return returnError("Failed to load legacy provider");
    };
    defer _ = c.OSSL_PROVIDER_unload(legacy_provider);

    // Create SSL context
    const ssl_ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse {
        return returnError("Failed to create SSL context");
    };
    defer _ = c.SSL_CTX_free(ssl_ctx);

    // Load client certificate from .pfx file
    const pfx_path = "c:/madeiras/erp/certificates/client.pfx";
    const pfx_file = c.BIO_new_file(pfx_path, "rb") orelse {
        return returnError("Failed to open PFX file");
    };
    defer _ = c.BIO_free(pfx_file);

    const pfx = c.d2i_PKCS12_bio(pfx_file, null) orelse {
        return returnError("Failed to load PFX");
    };
    defer _ = c.PKCS12_free(pfx);

    var cert: ?*c.X509 = null;
    var key: ?*c.EVP_PKEY = null;
    if (c.PKCS12_parse(pfx, "123", &key, &cert, null) != 1) {
        return returnError("Failed to parse PFX");
    }
    defer {
        if (cert) |_| _ = c.X509_free(cert.?);
        if (key) |_| _ = c.EVP_PKEY_free(key.?);
    }

    if (c.SSL_CTX_use_certificate(ssl_ctx, cert) != 1) {
        return returnError("Failed to use certificate");
    }

    if (c.SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1) {
        return returnError("Failed to use private key");
    }

    // Load CA certificates
    const cacerts_path = "c:/madeiras/erp/certificates/cacerts.pem"; // Relative path for portability
    if (c.SSL_CTX_load_verify_locations(ssl_ctx, cacerts_path, null) != 1) {
        return returnError("Failed to load CA certs");
    }
    c.SSL_CTX_set_verify(ssl_ctx, c.SSL_VERIFY_PEER, null);

    // Create a BIO for the HTTPS connection
    const host = "homologacao.nfe.sefa.pr.gov.br:443";
    const bio = c.BIO_new_ssl_connect(ssl_ctx) orelse {
        return returnError("Failed to create BIO");
    };
    defer _ = c.BIO_free_all(bio);

    var ssl: ?*c.SSL = null;
    if (c.BIO_get_ssl(bio, &ssl) != 1 or ssl == null) {
        return returnError("BIO_get_ssl failed");
    }

    if (c.BIO_set_conn_hostname(bio, host) != 1) {
        return returnError("Failed to set hostname");
    }

    if (c.BIO_do_connect(bio) != 1) {
        return returnError("Connection failed");
    }

    const verify_result = c.SSL_get_verify_result(ssl.?);
    if (verify_result != c.X509_V_OK) {
        return returnError("TLS verification failed");
    }

    const status_servico_request =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\">" ++
        "<soap:Header>" ++
        "<nfeCabecMsg>" ++
        "<cUF>41</cUF>" ++
        "<versaoDados>4.00</versaoDados>" ++
        "</nfeCabecMsg>" ++
        "</soap:Header>" ++
        "<soap:Body>" ++
        "<nfeDadosMsg>" ++
        "<consStatServ versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\">" ++
        "<tpAmb>2</tpAmb>" ++
        "<cUF>41</cUF>" ++
        "<xServ>STATUS</xServ>" ++
        "</consStatServ>" ++
        "</nfeDadosMsg>" ++
        "</soap:Body>" ++
        "</soap:Envelope>";

    const request = std.fmt.allocPrint(allocator, "POST /nfe/NFeStatusServico4 HTTP/1.1\r\n" ++
        "Host: homologacao.nfe.sefa.pr.gov.br\r\n" ++
        "Content-Type: application/soap+xml; charset=utf-8\r\n" ++
        "Content-Length: {}\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "{s}", .{ status_servico_request.len, status_servico_request }) catch {
        return returnError("Failed to allocate request");
    };
    defer allocator.free(request);

    if (request.len > std.math.maxInt(c_int)) {
        return returnError("Request length exceeds c_int maximum");
    }

    const request_len = @as(c_int, @intCast(request.len));
    if (c.BIO_write(bio, request.ptr, request_len) <= 0) {
        return returnError("Write failed");
    }

    var response = std.ArrayList(u8).init(allocator);
    defer response.deinit();
    var buf: [4096]u8 = undefined;

    while (true) {
        const read = c.BIO_read(bio, &buf, buf.len);
        if (read > 0) {
            response.appendSlice(buf[0..@as(usize, @intCast(read))]) catch {
                return returnError("Failed to append response");
            };
        } else if (read == 0) {
            break;
        } else if (c.BIO_should_retry(bio) != 0) {
            continue;
        } else {
            return returnError("Read failed");
        }
    }

    const body = response.items;
    const xml_start = std.mem.indexOf(u8, body, "<?xml") orelse 0;
    const response_str = body[xml_start..];

    // Check if response fits in static buffer
    if (response_str.len >= response_buffer.len) {
        return returnError("Response too large for static buffer");
    }

    // Copy response to static buffer
    @memcpy(response_buffer[0..response_str.len], response_str);
    response_buffer[response_str.len] = 0; // Ensure null termination
    return &response_buffer;
}

// Helper function to return an error message as a null-terminated string
fn returnError(msg: []const u8) ?[*:0]const u8 {
    if (msg.len >= response_buffer.len) {
        return null; // Error message too large
    }
    @memcpy(response_buffer[0..msg.len], msg);
    response_buffer[msg.len] = 0; // Ensure null termination
    return &response_buffer;
}
