# net

`net` is a networking package for the [Goose](https://github.com/aardappel/goose)
programming language. It gives a Goose program what the standard library
does not have yet:

- TCP connections and servers, with TLS on the client side
- URL parsing, resolution, percent-encoding, `data:` URLs and IDNA
- an HTTP/1.1 client with sessions, keep-alive, cookies, redirects,
  proxies, gzip and deflate, and streamed downloads
- a client that does not block: requests run on worker threads, in parallel
- DEFLATE, zlib and gzip decoders, which PNG decoders can use too

The C part (`src/net.c`) does only the work that needs the operating system:
sockets, name resolution and TLS. All the protocol logic is in Goose.

## Install

Declare the package in the root file of your program, then import the
modules that you use:

```goose
import net from "jdrobertso/net@v0.2.0";
import net.http;
```

At the first build, the Goose compiler fetches the package with git and
compiles its C with your C compiler. After that, it uses the cache in
`~/.goose`.

| Platform | TLS | What you need |
|---|---|---|
| Windows | Schannel, part of Windows | a C compiler that `goose toolchain` finds (MSVC or clang) |
| Linux | OpenSSL 3 or 1.1, loaded at run time | gcc or clang, the C library headers, and the OpenSSL runtime (`libssl3`). The OpenSSL headers are not necessary. |
| macOS | OpenSSL 3 from Homebrew or MacPorts, loaded at run time | the Xcode command line tools and `brew install openssl@3` |

We tested Windows 11 and Ubuntu 24.04. We did not test macOS. If the
package cannot find libssl, set `GOOSE_NET_LIBSSL` to the path of the
library.

## Modules

| Module | Namespace | Contents |
|---|---|---|
| `net` | `net::` | TCP connections as `Conn` handles, TLS, listeners, name resolution |
| `net.url` | `url::` | URL parsing (RFC 3986), resolution, percent-encoding, query and form helpers, `data:` URLs, IDNA host names |
| `net.http` | `http::` | the HTTP/1.1 client: `get`, `request`, `stream`, `Session`, `Options` |
| `net.client` | `http::` | the client that does not block: `Client`, `submit`, `poll`, `next`, `progress` |
| `net.cookie` | `cookie::` | the cookie jar of a session (RFC 6265) |
| `net.compress` | `compress::` | `inflate`, `zlib_decompress`, `gunzip`, `crc32`, `adler32` |

## Examples

### One request

```goose
import net from "jdrobertso/net@v0.2.0";
import net.http;
import std;

fn main() {
    let r = http::get("https://example.com/");
    if !http::ok(r) { print("error: ", http::error(r)); return; }
    let ctype, has = http::header(r, "content-type");
    print(r.status, " ", http::reason(r), ", ", http::body(r).len, " bytes of ", ctype);
}
```

### A session with cookies and keep-alive

```goose
var s = http::session();
let login = http::request(s, "POST", "https://example.com/login",
                          "Content-Type: application/x-www-form-urlencoded\r\n", "user=goose&pw=honk");
let page = http::get(s, "https://example.com/account");   // the same connection and the login cookie
http::save_cookies(s, "cookies.txt");
http::close(s);
```

Note: write `http::get(s, …)`, not `s.get(…)`. Goose looks for the function
of a method call in the namespace of the caller.

### A form body

```goose
var form: u8[>..] = [];
url::add_param(form, "q", "goose & duck");     // q=goose+%26+duck
url::add_param(form, "page", "2");
let r = http::request(s, "POST", "https://example.com/search",
                      "Content-Type: application/x-www-form-urlencoded\r\n", form);
```

### A large download to a file

`stream` gives each part of the body to a block, as the part arrives. Thus
the download needs only a small, fixed quantity of memory.

```goose
let r = http::stream(s, "GET", "https://example.com/big.iso") { chunk, total =>
    append_file("big.iso", chunk);
};
```

### A TCP server

```goose
let l = net::listen("127.0.0.1", 8080);
loop {
    let c = net::accept(l);
    var line: u8[>..] = [];
    if net::recv(c, line) > 0 { net::send(c, line); }   // echo one message
    net::close(c);
}
```

### Requests that do not block

`net.client` runs requests on worker threads. The calling thread continues,
for example to draw the frames of a window. `submit` returns an id at once.
`poll` gives a complete response if there is one, and never waits.

```goose
import net.client;

var c = http::client();                         // 4 worker threads
let page = http::submit(c, "GET", "https://example.com/");
let logo = http::submit(c, "GET", "https://example.com/logo.png");
while http::pending(c) > 0 {
    let id, r = http::poll(c);
    if id == page { show_page(r); }
    if id == logo { show_image(r); }
    draw_frame();
}
http::close(c);
```

The client needs `goose build`, because it starts threads. See
[Threads](#threads).

More examples are in `examples/`: `fetch.goose` (a small curl),
`session.goose`, `parallel.goose` (the client that does not block) and
`raw.goose` (only the `net` layer).

## The design

### Memory

A `http::Response` owns one buffer. The buffer holds the final URL, then the
header block, then the body. `final_url`, `head`, `header`, `body` and
`error` return slices into that buffer. Thus they copy nothing.

A `url::Url` is a set of slices into the text that you parse. It is valid
only while that text is valid. The functions that make text, for example
`url::resolve`, write into a builder that you own.

`http::Options` holds no references. Its strings are inline, with a fixed
capacity. Thus a `Session` can keep it, and a thread queue can carry it.

### Errors

A failed request returns a `Response` with status 0, and its body holds
the reason. Thus one return type covers success and failure. Use
`http::ok(r)` and `http::error(r)`.

In `net`, a call that fails returns a zero `Conn`, `false` or `-1`. Then
`net::error()` gives the reason. Each thread has its own last error.

The decoders in `compress` return `false` and a reason. Each decoder has a
`limit` on its output, so that a small hostile input cannot expand to a
very large output.

### Security

- TLS always checks the certificate chain and the host name. There is no
  option to switch the check off.
- The client accepts TLS 1.2 and TLS 1.3 only.
- A cookie with `Secure` comes only from `https`, and goes only to `https`.
- `Options.max_bytes` limits the size of a body after decoding.
- The client does not read `HTTP_PROXY` in capitals, because a CGI request
  can set it ("httpoxy").

### Threads

The handle table in C has a lock, and each thread has its own last error.
Thus several `thread_fn` workers can download at the same time. Each
worker must use its own connections and its own `Session`.

`net.client` uses this. Each worker is a `thread_fn` with its own
`Session`, so a worker keeps its connections open between jobs. The
requests and the responses go through the typed queues of Goose as flat
values. The client keeps the cookie jar. Each job takes a copy of the
jar, and the worker sends back only the changes. Thus two requests at the
same time cannot lose the cookies of each other. A program can have only
one `Client` at a time, because all the workers share the same queues.

Threads need `goose build`. The in-process run (`goose file.goose`) cannot
start them, and the compiler says so. The functions in `net.http` do not
use threads, so they work in the two forms. An executable from
`goose build` needs nothing that Windows does not have. On Linux, it needs
`libssl3` for TLS.

## API reference

### `net`

| Function | Description |
|---|---|
| `connect(host, port, tls = false, timeout_ms = 15000) -> Conn` | Connects, and with `tls` does the TLS handshake. The time limit also applies to each send and recv. |
| `send(c, data) -> bool` | Sends all the bytes. |
| `recv(c, out, max = 16384) -> i64` | Appends the bytes that arrived. 0 is the end of the stream, -1 is an error or a timeout. |
| `recv_all(c, out, limit) -> bool` | Reads until the end of the stream. |
| `start_tls(c, host) -> bool` | Starts TLS on an open connection, for example a proxy tunnel. |
| `set_timeout(c, ms) -> bool` | Changes the time limit. |
| `close(c)` | Closes the connection. A closed or zero `Conn` has no effect. |
| `listen(host, port, backlog = 0) -> Conn` | Opens a listener. Port 0 lets the system select a port. |
| `accept(listener, timeout_ms = 0) -> Conn` | Waits for the next connection. |
| `local_port(c) -> i64`, `peer(c, out) -> i64` | Give the local port, and the address and port of the peer. |
| `resolve(host, out) -> bool` | Appends the addresses of a host, one on each line. |
| `ok(c) -> bool`, `error() -> u8[>..]` | Check a `Conn`, and read the last error of this thread. |

### `url`

| Function | Description |
|---|---|
| `parse(text) -> Url, bool` | Splits an absolute or relative URI reference. |
| `resolve(base, ref, out)` | Appends the absolute URL of a reference (RFC 3986 §5.2). |
| `format(out, u)`, `format_target(out, u)` | Write the URL, or the target of a request line. |
| `port_or_default(u) -> i64`, `scheme_is(u, s) -> bool` | The port for a connection, and a scheme test that ignores case. |
| `percent_encode(out, s, form = false)`, `percent_decode(out, s, form = false) -> bool` | Encode or decode one component. With `form`, a space is `+`. |
| `each_param(query) { name, value => }`, `add_param(out, name, value)` | Read and write `a=1&b=2`. |
| `decode_data(text, out) -> media_type, bool` | Decodes a `data:` URL (RFC 2397). |
| `host_to_ascii(out, host) -> bool` | The IDNA form of a host: `münchen.de` becomes `xn--mnchen-3ya.de`. |

### `http`

| Function | Description |
|---|---|
| `get(url, opts)`, `head_request(url, opts)`, `request(method, url, headers, body, opts)` | One request with no state after it. |
| `session(opts) -> Session`, `close(s)` | A session keeps a connection pool and a cookie jar. |
| `get(s, url)`, `request(s, method, url, headers, body)` | A request in a session. |
| `stream(s, method, url, headers, body) { chunk, total => }` | Gives the body in parts. `total` is the Content-Length or -1. |
| `ok(r)`, `error(r)`, `final_url(r)`, `reason(r)`, `head(r)`, `body(r)` | Read a `Response`. |
| `header(r, name) -> value, bool`, `each_header(r) { name, value => }` | Read the headers. Names ignore case. |
| `load_cookies(s, path)`, `save_cookies(s, path)` | Read and write the cookie jar of a session. |

`headers` are extra request lines, each one `"Name: value\r\n"`. A line with
the name of a default header (`User-Agent`, `Accept`, `Accept-Encoding`,
`Cookie`) replaces that default.

The fields of `Options`, with their defaults:

| Field | Default | Meaning |
|---|---|---|
| `max_redirects` | 10 | the maximum count of redirects to follow |
| `timeout_ms` | 15000 | the time limit for the connect and for each wait for data |
| `max_bytes` | 256 MB | the largest body, after decoding. `stream` ignores it. |
| `decompress` | true | ask for gzip and deflate, and decode the body |
| `keep_alive` | true | keep connections in the pool of a session |
| `cookies` | true | store and send cookies with the jar of a session |
| `proxy` | "" | an `http://[user:password@]host:port` proxy |
| `use_env_proxy` | true | when `proxy` is empty, use `http_proxy`, `HTTPS_PROXY` and `NO_PROXY` |
| `no_proxy` | "" | hosts that do not use the proxy, for example `"localhost,.example.com"` |
| `user_agent` | "goose-net/0.2" | the default `User-Agent` |

A Goose struct literal must give its fields in this sequence, for example
`http::Options { timeout_ms: 5000, proxy: "http://proxy:3128", .. }`.

### `net.client`

These functions are in the `http::` namespace.

| Function | Description |
|---|---|
| `client(opts, workers = 4) -> Client` | Starts the worker threads. |
| `submit(c, method, url, headers = "", body = "", progress = false) -> i64` | Starts a request and returns its id at once. |
| `poll(c) -> id, Response` | A complete response, or -1. It never waits. |
| `next(c, timeout_ms = -1) -> id, Response` | Waits for the next complete response. -1 when the time limit expires, or when no request is in flight. |
| `progress(c) -> Progress, bool` | The next `Progress { id, got, total }` message of a request with `progress`. |
| `pending(c) -> i64` | The count of requests that are not complete. |
| `close(c)` | Stops the workers, after the jobs in the queue. |
| `load_cookies(c, path)`, `save_cookies(c, path)` | Read and write the cookie jar of the client. |

### `cookie` and `compress`

`cookie::store(jar, set_cookie, url, now)` and
`cookie::format_header(out, jar, url, now)` are the jar operations that a
session uses. You can use them with your own jar. The comment at the top of
`cookie.goose` gives the format of the jar.

`compress::gunzip(data, out, limit)`, `compress::zlib_decompress(…)` and
`compress::inflate(…)` append the decoded bytes to `out`, and return
`ok, reason`.

## Tests

```bash
./run_tests.sh             # Linux and macOS
./run_tests.ps1            # Windows
./run_tests.sh --online    # also the tests that use the internet
```

The tests for `url`, `cookie`, `compress` and `net` use no network.
`http_test` starts a local HTTP server on worker threads, so it needs a
native build. With `--online`, it also sends HTTPS through a local CONNECT
proxy to example.com.

Git keeps only the small test data, less than 1 KB, so the package that users
fetch stays small. `test/make_fixtures.py` makes the large `compress` cases
in `test/data/gen`. The test runners call it when Python is available.
Without these cases, `compress_test` skips them and says so.

## Limits

These features are not in the package yet:

- HTTP/2 and HTTP/3. The client speaks HTTP/1.1 only.
- Brotli (`br`). The client does not ask for it, so servers send gzip.
- TLS for servers. `listen` gives plain TCP only.
- The Public Suffix List for cookies, and the Unicode mapping of IDNA (UTS #46).
- Request bodies in parts (chunked uploads), multipart forms and `Expect: 100-continue`.
- An event loop on one thread. `net.client` uses worker threads, so it
  needs `goose build`.
- Cancellation of a request that is in flight.

## License

Apache License 2.0. See `LICENSE`.
