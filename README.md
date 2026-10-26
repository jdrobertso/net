# net

`net` is a Goose package for network access. It gives a browser, or any
other Goose program, the network functions that the Goose standard library
does not have yet. It has three modules:

| Module | Contents |
|---|---|
| `net` | TCP connections, plain or with TLS, as opaque `Conn` handles. Also name resolution. |
| `net.url` | URL parsing (RFC 3986), and resolution of relative references against a base URL. |
| `net.http` | An HTTP/1.1 client. It follows redirects and reads chunked and Content-Length bodies. |

The C part (`src/net.c`) does only the work that needs the operating system:
sockets, DNS and TLS. All the protocol logic is in Goose.

## Use the package

Declare the package in the root file of your program. The path is relative
to that file:

```goose
import net from "../net";
import net.http;
import net.url;

fn main() {
    let r = http::get("https://example.com/");
    if !http::ok(r) { print("error: ", http::error(r)); return; }
    print(r.status, " ", http::reason(r), " from ", http::final_url(r));
    let ctype, has = http::header(r, "content-type");
    print(http::body(r).len, " bytes of ", ctype);
}
```

The first run builds the C part with your C compiler (MSVC on this machine).
After that, `goose` uses the cached build in `~/.goose`.

## Memory model

A `http::Response` owns one buffer: the final URL, then the header block,
then the body. `final_url`, `head`, `header`, `body` and `error` return
slices into that buffer, so they copy nothing. A failed request returns a
`Response` with status 0, and its body holds the error message. Thus one
return type covers success and failure.

A `url::Url` is a set of slices into the text that you parse. It is valid
only while that text is valid. `url::resolve` writes a new URL into a
builder that you own.

## TLS

On Windows, TLS uses Schannel, so the package needs no third-party
libraries. Schannel checks the certificate chain and the host name against
the Windows certificate store. The package supports TLS 1.2 and TLS 1.3,
with TLS 1.3 session tickets. It rejects expired, self-signed,
untrusted-root and wrong-host certificates.

On Linux and macOS, plain TCP works. A TLS connection fails with a clear
error until the package gets a second TLS backend. We did not test the
non-Windows code.

## Threads

The handle table has a lock, and each thread keeps its own last error.
Thus a browser can download resources on several `thread_fn` workers at
the same time. Each worker uses its own connections. Note that threads
need `goose build`. The in-process TinyCC run does not support them.

## Run the tests and examples

```bash
cd test && goose url_test.goose                         # offline: parsing and RFC 3986 §5.4 resolution
cd examples && goose fetch.goose -- https://example.com/ # a small curl
cd examples && goose raw.goose -- example.com            # only the net layer, with a hand-written request
```

## Limits and next steps

The current version does not have these features. The list is roughly in
order of value for a browser:

1. **Compression.** The client sends `Accept-Encoding: identity`. A gzip
   and deflate decoder in Goose would make downloads smaller.
2. **Keep-alive and connection reuse.** Each request opens a new
   connection. A page with many images needs a connection pool for each host.
3. **Cookies.** `http::each_header` gives all `Set-Cookie` lines, but no
   cookie store exists yet.
4. **Character sets.** The body is raw bytes. The HTML layer must decode
   the body with the charset from `Content-Type`.
5. **Non-blocking I/O.** Each call blocks its thread. Use worker threads
   for now.
6. **Others:** a TLS backend for other platforms, HTTP/2, proxies,
   `data:` and `file:` URLs, and IDNA/punycode host names.
