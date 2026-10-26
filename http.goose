// An HTTP/1.1 client on top of net.
//
// It follows redirects and reads bodies with a Content-Length, with chunked
// encoding, or until the end of the connection. It asks for gzip and
// deflate compression and decodes the body. Thus body() gives the decoded
// bytes. The headers stay as the server sent them.
//
// One request, with no state after it:
//
//   let r = http::get("https://example.com/");
//   if http::ok(r) {
//       print(r.status, " ", http::final_url(r), " ", http::body(r).len, " bytes");
//   } else {
//       print("failed: ", http::error(r));
//   }
//
// A Session keeps connections open between requests (keep-alive) and keeps
// a cookie jar. Use one Session for many requests to the same hosts:
//
//   var s = http::session();
//   let a = http::get(s, "https://example.com/a");
//   let b = http::get(s, "https://example.com/b");   // the same connection
//   http::close(s);
//
// A Response owns one buffer. The buffer holds the final URL, then the
// header lines, then the body. All the functions below give views into
// this buffer. A failed request gives a Response with status 0, and its
// body is the error message. Thus the caller always has one value to
// return, keep or send to a different function.
//
// Proxies: Options.proxy gives an http:// proxy. When it is empty, the
// client uses the environment: http_proxy, HTTPS_PROXY (or https_proxy)
// and NO_PROXY (or no_proxy). The client sends https requests through the
// proxy with CONNECT, and http requests in absolute form. The client does
// not read HTTP_PROXY in capitals, because a CGI request can set it.

namespace http;

import std;
import os;             // the environment, and the clock for cookies and the pool
import base64;
import net;
import url;            // the url.goose of this package
import compress;       // the compress.goose of this package
import cookie;         // the cookie.goose of this package

// The strings in Options are inline, with a fixed capacity. Thus Options
// holds no references. A Session can keep it, and a thread queue can carry it.
struct Options {
    max_redirects: i64 = 10,
    timeout_ms: i64 = 15000,          // for the connect, and for each wait for data
    max_bytes: i64 = 1 << 28,         // the largest body that the client accepts, after decoding: 256 MB
    decompress: bool = true,          // ask for gzip and deflate, and decode the body
    keep_alive: bool = true,          // keep connections in the pool of the Session
    cookies: bool = true,             // store and send cookies with the jar of the Session
    proxy: u8[..512] = "",            // "http://[user:password@]host:port"
    use_env_proxy: bool = true,       // when proxy is empty, use the environment
    no_proxy: u8[..1024] = "",        // the hosts that do not use proxy: "localhost,.example.com"
    user_agent: u8[..256] = "goose-net/0.1",
}

struct Response {
    status: i64,           // 0 when the request failed. Then the body is the reason.
    redirects: i64,        // the count of redirects that the client followed
    url_end: i64,          // data[..url_end] is the URL that sent the response
    head_end: i64,         // data[url_end..head_end] is the status line and the headers
    data: u8[>..],
}

fn ok(r: const Response&) -> bool { r.status > 0 }
fn final_url(r: const Response&) -> const u8[:] { r.data[..r.url_end] }
fn head(r: const Response&) -> const u8[:] { r.data[r.url_end..r.head_end] }
fn body(r: const Response&) -> const u8[:] { r.data[r.head_end..] }
fn error(r: const Response&) -> const u8[:] { if r.status > 0 { r.data[0..0] } else { body(r) } }

// Returns the reason phrase of the status line, for example "OK" or "Not Found".
fn reason(r: const Response&) -> const u8[:] {
    let h = head(r);
    let eol = find(h, "\r\n");
    let line = if eol >= 0 { h[..eol] } else { h };
    let sp1 = find(line, " ");
    guard sp1 >= 0 else { return line[0..0]; }
    let sp2 = find(line[sp1 + 1..], " ");
    guard sp2 >= 0 else { return line[line.len..]; }
    return line[sp1 + 1 + sp2 + 1..];
}

// Returns the trimmed value of the first header with the name `name`. The
// comparison ignores case.
fn header(r: const Response&, name: u8[:]) -> const u8[:], bool { return find_header(head(r), name); }

// Calls F with the name and the value of each header, in sequence. Use it
// to read Set-Cookie and the other headers that can occur more than once.
fn each_header<F>(r: const Response&) {
    let h = head(r);
    let eol = find(h, "\r\n");
    guard eol >= 0;
    each_split(h[eol + 2..], "\r\n") {
        let colon = find(it, ":");
        if colon > 0 { F(trim(it[..colon]), trim(it[colon + 1..])); }
    };
}

fn is_redirect_status(status: i64) -> bool {
    status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

fn is_redirect(r: const Response&) -> bool { is_redirect_status(r.status) }

// ---------------------------------------------------------------- sessions

let POOL_SIZE = 8;
let IDLE_NS = 30 * 1000000000;     // the client closes a pooled connection after 30 s of no use

// One idle connection in the pool. `host` and `port` are the end of the
// TCP connection: the proxy for a plain request through a proxy, else the
// server.
struct Slot { conn: net::Conn, host: u8[..255], port: i64, tls: bool, proxied: bool, idle_since: i64 }

struct Session {
    opts: Options,
    pool: Slot[..8],
    cookies: u8[>..],      // the cookie jar (see cookie.goose)
}

fn session(opts: Options = Options { .. }) -> Session {
    Session { opts: opts, pool: [], cookies: [] }
}

// Closes all the connections in the pool. The cookie jar stays.
fn close(s: Session&) {
    for e in s.pool { net::close(e.conn); }
    s.pool.clear();
}

// Replaces the cookie jar with the jar in the file at `path`, for example
// a file from save_cookies. Returns false if the file cannot be read.
fn load_cookies(s: Session&, path: const u8[:]) -> bool {
    var text: u8[>..] = [];
    guard read_file(path, text) else { return false; }
    s.cookies.clear();
    s.cookies.append(text);
    return true;
}

// Writes the cookies with an expiry time to the file at `path`. The
// function does not write session cookies.
fn save_cookies(s: const Session&, path: const u8[:]) -> bool {
    var text: u8[>..] = [];
    cookie::persistent(text, s.cookies, now_s());
    return write_file_atomic(path, text);
}

fn now_s() -> i64 { time_ns() / 1000000000 }

fn take_conn(s: Session&, host: u8[:], port: i64, tls: bool, proxied: bool) -> net::Conn {
    let now = time_ns();
    var i = 0;
    while i < s.pool.len {
        let e = s.pool[i];
        if now - e.idle_since > IDLE_NS {
            net::close(e.conn);
            s.pool.swap_remove(i);
            continue;
        }
        if e.port == port && e.tls == tls && e.proxied == proxied && url::equal_ci(e.host, host) {
            s.pool.swap_remove(i);
            return e.conn;
        }
        i++;
    }
    return net::Conn { id: 0 };
}

fn give_conn(s: Session&, c: net::Conn, host: u8[:], port: i64, tls: bool, proxied: bool) {
    guard host.len <= 255 else { net::close(c); return; }
    if s.pool.len == POOL_SIZE {
        net::close(s.pool[0].conn);
        s.pool.swap_remove(0);
    }
    var e = Slot { conn: c, host: [], port: port, tls: tls, proxied: proxied, idle_since: time_ns() };
    e.host.append(host);
    s.pool.push(e);
}

// ---------------------------------------------------------------- requests

// The functions with a Session use its pool and its cookie jar. The
// functions without a Session make a new Session for the one request. Its
// cookies apply only to the redirects of that request.

fn get(target: const u8[:], opts: Options = Options { .. }) -> Response {
    var s = session(opts);
    s.opts.keep_alive = false;
    return request_core(s, "GET", target, "", "", false) { chunk, total => };
}

fn get(s: Session&, target: const u8[:]) -> Response {
    request_core(s, "GET", target, "", "", false) { chunk, total => }
}

fn head_request(target: const u8[:], opts: Options = Options { .. }) -> Response {
    var s = session(opts);
    s.opts.keep_alive = false;
    return request_core(s, "HEAD", target, "", "", false) { chunk, total => };
}

// `headers` are more request lines, each in the form "Name: value\r\n". A
// line with the name of a default header (User-Agent, Accept,
// Accept-Encoding, Cookie) replaces that default. A `body` gets a
// Content-Length header. After a 303, the next request is a GET with no
// body. After a 301 or a 302 for a POST, the same change occurs, as in
// browsers.
fn request(method: const u8[:], target: const u8[:], headers: const u8[:] = "",
           body: const u8[:] = "", opts: Options = Options { .. }) -> Response {
    var s = session(opts);
    s.opts.keep_alive = false;
    return request_core(s, method, target, headers, body, false) { chunk, total => };
}

fn request(s: Session&, method: const u8[:], target: const u8[:], headers: const u8[:] = "",
           body: const u8[:] = "") -> Response {
    request_core(s, method, target, headers, body, false) { chunk, total => }
}

// Sends a request and calls F with each part of the body as it arrives:
// F(chunk, total). `total` is the Content-Length, or -1 if the response
// has none. The Response that stream returns has an empty body. Thus a
// large download needs only a small, fixed quantity of memory. The request
// asks for no compression, so the parts are the bytes of the resource.
// Options.max_bytes does not apply. F gets only the body of the final
// response, not the bodies of redirects.
fn stream<F>(s: Session&, method: const u8[:], target: const u8[:], headers: const u8[:] = "",
             body: const u8[:] = "") -> Response {
    request_core(s, method, target, headers, body, true) { chunk, total => F(chunk, total); }
}

fn request_core<F>(s: Session&, method: const u8[:], target: const u8[:], headers: const u8[:],
                   body: const u8[:], streaming: bool) -> Response {
    let t = trim(target);
    if t.len >= 5 && url::equal_ci(t[..5], "data:") {
        return data_response(t, streaming) { chunk, total => F(chunk, total); };
    }

    // Copy the arguments. The cookie jar in `s` changes during the request,
    // and these copies cannot point into it.
    var cur: u8[>..] = [];
    cur.append(t);
    var meth: u8[>..] = [];
    meth.append(method);
    var extra: u8[>..] = [];
    extra.append(headers);
    var payload: u8[>..] = [];
    payload.append(body);
    var hops = 0;
    let o = s.opts;

    loop {
        let u, parsed = url::parse(cur);
        guard parsed else { return failure(cur, "the URL syntax is not valid"); }
        guard u.has_scheme && u.host.len > 0 else { return failure(cur, "the URL is not absolute"); }
        let tls = url::scheme_is(u, "https");
        guard tls || url::scheme_is(u, "http") else {
            return failure(cur, str("this client does not support the scheme '", u.scheme, "'"));
        }
        var host: u8[>..] = [];
        guard url::host_to_ascii(host, u.host) else { return failure(cur, "the host name is not valid"); }
        let port = url::port_or_default(u);
        // The URL with the ASCII host, for the cookie jar.
        var au = u;
        au.host = host;

        // The proxy, if this request uses one.
        var proxy_text: u8[>..] = [];
        find_proxy(o, tls, host, proxy_text);
        let proxied = proxy_text.len > 0;
        let pu, pok = url::parse(proxy_text);
        guard !proxied || (pok && url::scheme_is(pu, "http") && pu.host.len > 0) else {
            return failure(cur, str("the proxy URL is not a valid http:// URL: ", proxy_text));
        }
        var proxy_auth: u8[>..] = [];
        if proxied && pu.userinfo.len > 0 {
            var plain: u8[>..] = [];
            url::percent_decode(plain, pu.userinfo);
            proxy_auth.append("Basic ");
            base64::encode(proxy_auth, plain);
        }
        // With a proxy, the TCP connection always goes to the proxy. A plain
        // request goes to the proxy itself. An https request goes through a
        // CONNECT tunnel to the server.
        let via_proxy = proxied && !tls;
        let tcp_host = if proxied { pu.host } else { host[..] };
        let tcp_port = if proxied { if pu.port >= 0 { pu.port } else { 80 } } else { port };
        // The pool key: the far end of the tunnel, else the TCP connection.
        let conn_host = if proxied && tls { host[..] } else { tcp_host };
        let conn_port = if proxied && tls { port } else { tcp_port };

        var cookie_text: u8[>..] = [];
        if o.cookies { cookie::format_header(cookie_text, s.cookies, au, now_s()); }
        var req: u8[>..] = [];
        format_request(req, meth, u, host, extra, payload, cookie_text, o, via_proxy,
                       if via_proxy { proxy_auth[..] } else { proxy_auth[0..0] }, streaming);

        // A pooled connection can be closed by the server while it is idle.
        // Then the client tries once more on a new connection. A POST never
        // uses a pooled connection, because a retry could send it two times.
        let may_reuse = o.keep_alive && meth != "POST" && meth != "PATCH";
        var c = if may_reuse { take_conn(s, conn_host, conn_port, tls, proxied) } else { net::Conn { id: 0 } };
        var raw: u8[>..] = [];
        var chunks: u8[>..] = [];
        var f = Frame { .. };
        for attempt in 2 {
            let reused = net::ok(c);
            if !reused {
                c = net::connect(tcp_host, tcp_port, tls && !proxied, o.timeout_ms);
                guard net::ok(c) else { return failure(cur, net::error()); }
                if tls && proxied {
                    var why: u8[>..] = [];
                    if !tunnel(c, host, port, proxy_auth, why) {
                        net::close(c);
                        return failure(cur, why);
                    }
                }
            }
            f = exchange(c, cur, req, meth == "HEAD", reused, streaming, raw, chunks, o.max_bytes) {
                chunk, total => F(chunk, total);
            };
            if !f.stale { break; }
            net::close(c);
            c = net::Conn { id: 0 };
            raw.clear();
            chunks.clear();
        }

        let head_text = raw[f.start..f.head_end - 4];
        if o.cookies {
            let now = now_s();
            each_named(head_text, "set-cookie") { cookie::store(s.cookies, it, au, now); };
        }

        // Keep the connection only if all of these are true:
        // - the response ended at a known position,
        // - no bytes came after the response,
        // - the server did not ask to close the connection.
        let conn_value, has_conn = find_header(head_text, "connection");
        let server_keeps = if f.http11 { !(has_conn && contains_ci(conn_value, "close")) }
                           else { has_conn && contains_ci(conn_value, "keep-alive") };
        if o.keep_alive && f.framed && raw.len == f.end && server_keeps {
            give_conn(s, c, conn_host, conn_port, tls, proxied);
        } else {
            net::close(c);
        }

        let loc, has_loc = find_header(head_text, "location");
        if is_redirect_status(f.status) && has_loc {
            guard hops < o.max_redirects else {
                return failure(cur, str("the server sent more than ", o.max_redirects, " redirects"));
            }
            if f.status == 303 || ((f.status == 301 || f.status == 302) && meth == "POST") {
                meth.clear();
                meth.append("GET");
                payload.clear();
            }
            var next: u8[>..] = [];
            url::resolve(u, loc, next);
            // If the Location has no fragment, the new URL keeps the old fragment (RFC 9110 §10.2.2).
            let nu, _ = url::parse(next);
            if u.has_fragment && !nu.has_fragment { next.push('#'); next.append(u.fragment); }
            cur.clear();
            cur.append(next);
            hops++;
            continue;
        }

        let content = if f.chunked { chunks[..] } else { raw[f.body_start..f.body_end] };
        var decoded: u8[>..] = [];
        var final_body = content;
        let ce, has_ce = find_header(head_text, "content-encoding");
        if o.decompress && !streaming && has_ce && content.len > 0 && !url::equal_ci(ce, "identity") {
            guard find(ce, ",") < 0 else {
                return failure(cur, str("the response has more than one content coding: ", ce));
            }
            let dok, why = decode_body(ce, content, decoded, o.max_bytes);
            guard dok else { return failure(cur, str("cannot decode the ", ce, " body: ", why)); }
            final_body = decoded;
        }
        return Response {
            status: f.status,
            redirects: hops,
            url_end: cur.len,
            head_end: cur.len + head_text.len,
            data: concat3(cur, head_text, final_body),
        };
    }
}

fn failure(at: u8[:], why: u8[:]) -> Response {
    Response { status: 0, redirects: 0, url_end: at.len, head_end: at.len, data: concat(at, why) }
}

fn concat3(a: u8[:], b: u8[:], c: u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(a);
    out.append(b);
    out.append(c);
    return out;
}

// A Response for a data: URL, with no network.
fn data_response<F>(t: const u8[:], streaming: bool) -> Response {
    var bytes: u8[>..] = [];
    let mtype, ok = url::decode_data(t, bytes);
    guard ok else { return failure(t, "the data: URL is not valid"); }
    var h: u8[>..] = [];
    h.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    if mtype.len == 0 || mtype[0] == ';' { h.append("text/plain"); }
    if mtype.len == 0 { h.append(";charset=US-ASCII"); } else { h.append(mtype); }
    format(h, "\r\nContent-Length: ", bytes.len);
    if streaming { F(bytes[..], bytes.len); }
    let kept = if streaming { bytes[0..0] } else { bytes[..] };
    return Response { status: 200, redirects: 0, url_end: t.len, head_end: t.len + h.len, data: concat3(t, h, kept) };
}

// Decodes `content` with the Content-Encoding `coding` and appends the result to `out`.
fn decode_body(coding: u8[:], content: const u8[:], out: u8[>..]&, limit: i64) -> bool, const u8[:] {
    if url::equal_ci(coding, "gzip") || url::equal_ci(coding, "x-gzip") {
        return compress::gunzip(content, out, limit);
    }
    if url::equal_ci(coding, "deflate") {
        // "deflate" means zlib data (RFC 9110 §8.4.1.2). Some servers send
        // raw DEFLATE data. The client accepts the two forms.
        if compress::is_zlib(content) { return compress::zlib_decompress(content, out, limit); }
        return compress::inflate(content, out, limit);
    }
    return false, "this client does not support the content coding";
}

fn format_request(out: u8[>..]&, method: u8[:], u: url::Url, host: u8[:], headers: u8[:], body: u8[:],
                  cookies: u8[:], opts: Options, absolute: bool, proxy_auth: u8[:], streaming: bool) {
    out.append(method);
    out.push(' ');
    // A plain request to a proxy gives the full URL (absolute form).
    if absolute {
        for c in u.scheme { out.push(url::lower(c)); }
        out.append("://");
        format_host(out, u, host);
    }
    url::format_target(out, u);
    out.append(" HTTP/1.1\r\nHost: ");
    format_host(out, u, host);
    out.append("\r\n");
    let _, has_ua = find_header(headers, "user-agent");
    if !has_ua { format(out, "User-Agent: ", opts.user_agent, "\r\n"); }
    let _, has_accept = find_header(headers, "accept");
    if !has_accept { out.append("Accept: */*\r\n"); }
    let _, has_ae = find_header(headers, "accept-encoding");
    if !has_ae {
        let compressed = opts.decompress && !streaming;
        out.append(if compressed { "Accept-Encoding: gzip, deflate\r\n" } else { "Accept-Encoding: identity\r\n" });
    }
    let _, has_cookie = find_header(headers, "cookie");
    if !has_cookie && cookies.len > 0 { format(out, "Cookie: ", cookies, "\r\n"); }
    if proxy_auth.len > 0 { format(out, "Proxy-Authorization: ", proxy_auth, "\r\n"); }
    // HTTP/1.1 keeps the connection open by default.
    if !opts.keep_alive { out.append("Connection: close\r\n"); }
    out.append(headers);
    if headers.len > 0 && !ends_with(headers, "\r\n") { out.append("\r\n"); }
    if body.len > 0 || method == "POST" || method == "PUT" || method == "PATCH" {
        format(out, "Content-Length: ", body.len, "\r\n");
    }
    out.append("\r\n");
    out.append(body);
}

// Writes the host for a Host header or a URL: the ASCII host, in brackets
// for IPv6, and the port if the URL has one.
fn format_host(out: u8[>..]&, u: url::Url, host: u8[:]) {
    if u.ipv6 { out.push('['); out.append(host); out.push(']'); } else { out.append(host); }
    if u.port >= 0 { out.push(':'); format(out, u.port); }
}

// ---------------------------------------------------------------- proxies

// True if `host` is in a NO_PROXY list: "*", or names separated by commas.
// A name matches the host and its subdomains.
fn no_proxy_match(list: u8[:], host: u8[:]) -> bool {
    var p = 0;
    while p < list.len {
        var e = find(list[p..], ",");
        e = if e < 0 { list.len } else { p + e };
        var name = trim(list[p..e]);
        p = e + 1;
        if name == "*" { return true; }
        if name.len > 0 && name[0] == '.' { name = name[1..]; }
        // The match ignores a port in the entry. It uses only the host.
        let colon = rfind(name, ":");
        if colon > 0 && find(name, "]") < 0 { name = name[..colon]; }
        guard name.len > 0 else { continue; }
        if url::equal_ci(host, name) { return true; }
        if host.len > name.len && host[host.len - name.len - 1] == '.' &&
           url::equal_ci(host[host.len - name.len..], name) { return true; }
    }
    return false;
}

// Appends the proxy URL for a request to `host`, or nothing if the
// request goes direct.
fn find_proxy(o: Options, tls: bool, host: u8[:], out: u8[>..]&) {
    if o.proxy.len > 0 {
        if !no_proxy_match(o.no_proxy, host) { out.append(o.proxy); }
        return;
    }
    guard o.use_env_proxy;
    var np: u8[>..] = [];
    if !env("NO_PROXY", np) { env("no_proxy", np); }
    guard !no_proxy_match(np, host) && !no_proxy_match(o.no_proxy, host);
    var text: u8[>..] = [];
    if tls {
        if !env("HTTPS_PROXY", text) { env("https_proxy", text); }
    } else {
        env("http_proxy", text);
    }
    let v = trim(text);
    guard v.len > 0;
    // A proxy without a scheme, "host:port", is an http proxy.
    if find(v, "://") < 0 { out.append("http://"); }
    out.append(v);
}

// Opens a CONNECT tunnel through the proxy on `c` to host:port, then starts
// TLS for host. Returns false and the reason in `why` for a failure.
fn tunnel(c: net::Conn, host: u8[:], port: i64, auth: u8[:], why: u8[>..]&) -> bool {
    var req: u8[>..] = [];
    format(req, "CONNECT ", host, ":", port, " HTTP/1.1\r\nHost: ", host, ":", port, "\r\n");
    if auth.len > 0 { format(req, "Proxy-Authorization: ", auth, "\r\n"); }
    req.append("\r\n");
    guard net::send(c, req) else { why.append(net::error()); return false; }
    var raw: u8[>..] = [];
    loop {
        if find(raw, "\r\n\r\n") >= 0 { break; }
        guard raw.len < 65536 else { why.append("the proxy response headers are too large"); return false; }
        let n = net::recv(c, raw);
        guard n > 0 else {
            if n == 0 { why.append("the proxy closed the connection"); } else { why.append(net::error()); }
            return false;
        }
    }
    let end = find(raw, "\r\n\r\n") + 4;
    guard raw.len == end else { why.append("the proxy sent data after its CONNECT response"); return false; }
    let eol = find(raw, "\r\n");
    let line = raw[..eol];
    guard starts_with(line, "HTTP/") && line.len >= 12 && line[9] == '2' else {
        format(why, "the proxy refused the tunnel: ", line);
        return false;
    }
    guard net::start_tls(c, host) else { why.append(net::error()); return false; }
    return true;
}

// ---------------------------------------------------------------- responses

// The position of a response in the bytes that the client read for it.
// raw[start..head_end] is the status line and the headers, with the empty
// line at their end. The body is raw[body_start..body_end]. For a chunked
// body, the body is the decoded chunks. raw[..end] is the full message.
struct Frame {
    status: i64,
    start: i64,
    head_end: i64,
    body_start: i64,
    body_end: i64,
    end: i64,
    chunked: bool,
    framed: bool,      // the message ended at a known position, not at the end of the connection
    http11: bool,      // the server sent HTTP/1.1 (or a later version)
    stale: bool,       // the server closed a pooled connection before any byte of the response arrived
}

// Returns the trimmed value of the first header with the name `name` in a
// block of lines. The comparison ignores case. The status line has no name.
// Thus it never matches.
//
// This function uses a plain loop, not each_split. The root of a slice
// that each_split gives to a block is the parameter of each_split. This
// function must return such a slice, so that root is not correct here.
fn find_header(lines: const u8[:], name: u8[:]) -> const u8[:], bool {
    var p = 0;
    while p < lines.len {
        var e = find(lines[p..], "\r\n");
        e = if e < 0 { lines.len } else { p + e };
        let line = lines[p..e];
        let colon = find(line, ":");
        if colon > 0 && url::equal_ci(trim(line[..colon]), name) { return trim(line[colon + 1..]), true; }
        p = e + 2;
    }
    return lines[0..0], false;
}

// Calls F with the trimmed value of each header with the name `name`.
fn each_named<F>(lines: const u8[:], name: u8[:]) {
    each_split(lines, "\r\n") {
        let colon = find(it, ":");
        if colon > 0 && url::equal_ci(trim(it[..colon]), name) { F(trim(it[colon + 1..])); }
    };
}

fn contains_ci(s: u8[:], word: u8[:]) -> bool {
    guard word.len <= s.len else { return false; }
    for i in s.len - word.len + 1 { if url::equal_ci(s[i..i + word.len], word) { return true; } }
    return false;
}

// Sends the request and reads one full response into raw (and into chunks).
// Each failure ends the call of request_core. `at` is the URL for the error
// message. With `reused`, a connection that closes before the first byte
// of the response gives a Frame with `stale`, not a failure. With
// `streaming`, the function gives the body of the final response to F and
// keeps only a small part of it in raw.
fn exchange<F>(c: net::Conn, at: u8[:], req: u8[:], is_head: bool, reused: bool, streaming: bool,
               raw: u8[>..]&, chunks: u8[>..]&, limit: i64) -> Frame {
    let HEAD_LIMIT = 1 << 20;
    let COMPACT = 1 << 16;

    fn bail(why: u8[:]) { return failure(at, why) from request_core; }

    fn more() {
        let n = net::recv(c, raw);
        if n <= 0 && reused && raw.len == 0 { return Frame { stale: true, .. } from exchange; }
        if n == 0 { bail("the server closed the connection before the end of the response"); }
        if n < 0 { bail(net::error()); }
    }

    fn need(n: i64) { while raw.len < n { more(); } }

    // Returns the index of the next "\r\n" at or after p. It reads more bytes if necessary.
    fn line_end(p: i64) -> i64 {
        loop {
            let e = find(raw[p..], "\r\n");
            if e >= 0 { return p + e; }
            guard raw.len - p < 8192 else { bail("a chunk header line is too long"); }
            more();
        }
    }

    // Moves the bytes from `from` to the end of raw down to `to`, and
    // removes the rest. Streaming uses it to keep raw small.
    fn compact(to: i64, from: i64) {
        let rest = raw.len - from;
        if rest > 0 { copy_into(raw[to..to + rest], raw[from..from + rest]); }
        raw.resize(to + rest);
    }

    if !net::send(c, req) {
        if reused { return Frame { stale: true, .. }; }
        bail(net::error());
    }

    var f = Frame { .. };
    // Interim 1xx responses, for example 100 Continue, can come before the
    // real response. Skip them.
    loop {
        var scanned = f.start;
        loop {
            let e = find(raw[scanned..], "\r\n\r\n");
            if e >= 0 { f.head_end = scanned + e + 4; break; }
            scanned = max(f.start, raw.len - 3);
            guard raw.len - f.start < HEAD_LIMIT else { bail("the response headers are too large"); }
            more();
        }
        let line = raw[f.start..f.head_end];
        guard starts_with(line, "HTTP/") && line.len >= 12 && line[8] == ' ' else {
            bail("the server did not send an HTTP response");
        }
        let status, sok = parse_int(line[9..12]);
        guard sok && status >= 100 else { bail("the status line is not valid"); }
        f.status = status;
        f.http11 = !starts_with(line, "HTTP/1.0");
        if status >= 200 || status == 101 { break; }
        f.start = f.head_end;
    }

    f.body_start = f.head_end;
    f.body_end = f.head_end;
    f.end = f.head_end;
    f.framed = true;
    if is_head || f.status < 200 || f.status == 204 || f.status == 304 { return f; }

    // Get the framing facts as values. Then no slice into raw stays live,
    // and streaming can shrink raw.
    var is_chunked = false;
    var has_cl = false;
    var n = 0;
    var has_loc = false;
    {
        let h = raw[f.start..f.head_end];
        let te, has_te = find_header(h, "transfer-encoding");
        is_chunked = has_te && contains_ci(te, "chunked");
        let cl, hcl = find_header(h, "content-length");
        if hcl && !is_chunked {
            let v, okn = parse_int(cl);
            guard okn && v >= 0 else { bail("the Content-Length is not valid"); }
            has_cl = true;
            n = v;
        }
        let _, hl = find_header(h, "location");
        has_loc = hl;
    }
    // The client gives F only the body of the final response.
    let deliver = streaming && !(is_redirect_status(f.status) && has_loc);

    if is_chunked {
        f.chunked = true;
        var p = f.head_end;
        loop {
            let eol = line_end(p);
            var size_text = raw[p..eol];
            // Ignore chunk extensions.
            let semi = find(size_text, ";");
            if semi >= 0 { size_text = size_text[..semi]; }
            let size, okz = parse_int(trim(size_text), 16);
            guard okz && size >= 0 else { bail("a chunk size is not valid"); }
            p = eol + 2;
            if size == 0 {
                // Read the trailer lines, then the empty line at the end of the message.
                loop {
                    let e = line_end(p);
                    let blank = e == p;
                    p = e + 2;
                    if blank { break; }
                }
                break;
            }
            need(p + size + 2);
            guard raw[p + size..p + size + 2] == "\r\n" else {
                bail("a chunk does not end at the position that its size gives");
            }
            if deliver {
                F(raw[p..p + size], -1);
            } else {
                guard chunks.len + size <= limit else { bail("the response is larger than max_bytes"); }
                chunks.append(raw[p..p + size]);
            }
            p += size + 2;
            if deliver && p - f.head_end > COMPACT {
                compact(f.head_end, p);
                p = f.head_end;
            }
        }
        f.end = p;
        return f;
    }

    if has_cl {
        if deliver {
            var got = 0;
            loop {
                let avail = min(raw.len - f.head_end, n - got);
                if avail > 0 {
                    F(raw[f.head_end..f.head_end + avail], n);
                    got += avail;
                    compact(f.head_end, f.head_end + avail);
                }
                if got == n { break; }
                more();
            }
            return f;
        }
        guard n <= limit else { bail("the response is larger than max_bytes"); }
        need(f.head_end + n);
        f.body_end = f.head_end + n;
        f.end = f.body_end;
        return f;
    }

    // The response has no Content-Length and no chunked encoding. Thus the
    // body is all the bytes until the server closes the connection.
    f.framed = false;
    loop {
        if deliver && raw.len > f.head_end {
            F(raw[f.head_end..], -1);
            raw.resize(f.head_end);
        }
        guard deliver || raw.len - f.head_end <= limit else { bail("the response is larger than max_bytes"); }
        let n = net::recv(c, raw);
        if n == 0 { break; }
        if n < 0 { bail(net::error()); }
    }
    f.body_end = raw.len;
    f.end = raw.len;
    return f;
}
