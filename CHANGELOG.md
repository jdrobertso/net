# Changelog

## v0.1.0

The first release.

- `net`: TCP connections, TLS (Schannel on Windows, OpenSSL loaded at run
  time on Linux and macOS), `start_tls`, listeners, `accept`, name resolution.
- `net.url`: RFC 3986 parsing and resolution, percent-encoding, query and
  form helpers, `data:` URLs, IDNA host names with Punycode.
- `net.http`: an HTTP/1.1 client with sessions, a keep-alive pool, a cookie
  jar, redirects, gzip and deflate, proxies with CONNECT, and streamed bodies.
- `net.cookie`: an RFC 6265 cookie jar that can be saved to a file.
- `net.compress`: DEFLATE, zlib and gzip decoders, CRC-32 and Adler-32.
